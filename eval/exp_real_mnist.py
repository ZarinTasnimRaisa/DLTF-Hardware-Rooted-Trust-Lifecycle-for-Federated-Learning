"""
exp_real_mnist.py -- the accuracy result on a real model and real data.

WHY THIS IS THE HIGHEST-VALUE REMAINING EXPERIMENT

Every accuracy number in the paper comes from a synthetic gradient generator.
The isolation argument for that is legitimate and the paper makes it, but a
reviewer reads "0.520 versus 0.685" as a statement about a model, and it is not.
This runs the same comparison on the 409k-parameter CNN over non-IID MNIST that
the physical deployment already trains, so the paper can say the effect
survives contact with a real optimiser.

Note what this does NOT need: the three-machine deployment. Physical hosts are
what establish O1 (identity, enrolment, tiering). The accuracy claim needs real
gradients, not remote ones, so clients are local processes here and each one
does genuine local SGD on its own non-IID shard. That distinction should be
stated in the paper rather than blurred.

WHAT IT RUNS

  {no trust layer, DLTF} x {clean, label-flip poisoning} x seeds

  honest client   local SGD for E epochs on its shard
  poisoner        identical training on a label-flipped shard (y -> 9 - y),
                  which is the attack in Tolpegin et al. and produces a
                  genuinely misdirected gradient rather than a synthetic one

Accuracy is top-1 on the stratified validation split carved out by
fl.dataset.build_client_loaders, which no client trains on.

COST. Roughly (clients x epochs x rounds x seeds x 4 arms) local epochs. Start
with --quick to confirm the pipeline before committing to a full run:

    python -m eval.exp_real_mnist --quick --out results/
    python -m eval.exp_real_mnist --clients 8 --rounds 15 --seeds 3 --out results/

Output: real_mnist.csv (per round per arm), plus a printed summary table.
"""

import os
import csv
import copy
import time
import argparse
import statistics as st

import torch
import torch.nn.functional as F

from fl.model import MNISTModel
from fl.dataset import load_mnist, build_client_loaders
from fl.server import FederatedServer
from fl.aggregator import get_aggregator
from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from eval.scenarios import make_handle


def _write(path, header, rows):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print("wrote", path, "(%d rows)" % len(rows))


# --------------------------------------------------------------------------
# local training
# --------------------------------------------------------------------------

def local_update(flat_global, loader, epochs, lr, flip, device, max_batches,
                 scale=1.0):
    """Train from the broadcast parameters and return (DELTA, n_samples).

    fl/client.py unpacks the trainer's return as `update, num_samples`, and
    num_samples is not decoration: FedAvg weights each client by its sample
    count, and the non-IID partition gives clients shards of different sizes.
    Returning a bare list, as an earlier version did, both breaks the contract
    and would have silently equal-weighted the federation if it had not.

    Label flipping y -> 9 - y is applied inside the loop so the poisoner
    performs honest-looking optimisation toward a dishonest objective."""
    model = MNISTModel().to(device)
    model.set_parameters(flat_global)
    model.train()
    opt = torch.optim.SGD(model.parameters(), lr=lr, momentum=0.9)

    for _ in range(epochs):
        for b, (x, y) in enumerate(loader):
            if max_batches and b >= max_batches:
                break
            x, y = x.to(device), y.to(device)
            if flip:
                y = 9 - y
            opt.zero_grad()
            F.cross_entropy(model(x), y).backward()
            opt.step()

    new = model.get_parameters()
    delta = [n - g for n, g in zip(new, flat_global)]
    # Scaling attack: train honestly, then inflate the update so it dominates
    # the weighted average. This exercises a DIFFERENT detector stage from
    # label flipping -- norm against the participant median rather than cosine
    # against the robust reference -- which is what makes running both a real
    # evaluation instead of the same test twice.
    if scale != 1.0:
        delta = [d * scale for d in delta]
    n_samples = len(loader.dataset)
    if max_batches:
        n_samples = min(n_samples, max_batches * loader.batch_size)
    return delta, n_samples


@torch.no_grad()
def evaluate(flat, val_loader, device):
    model = MNISTModel().to(device)
    model.set_parameters(flat)
    model.eval()
    correct = total = 0
    for x, y in val_loader:
        x, y = x.to(device), y.to(device)
        correct += (model(x).argmax(1) == y).sum().item()
        total += y.numel()
    return correct / max(1, total)


class PlainServer:
    """No identity, no trust. Sample-weighted FedAvg. The control arm."""

    _warned = False

    def __init__(self, initial):
        self.global_params = list(initial)
        self.enrolled = set()
        self.rep = None
        self._agg = get_aggregator("fedavg")

    def enroll(self, handle):
        self.enrolled.add(handle.device_label)
        return {"device_id": handle.device_label, "tier": "NONE",
                "status": "ACTIVE"}

    def run_round(self, rid, handles):
        res = {h.device_label: h.train(rid, self.global_params)
               for h in handles if h.device_label in self.enrolled}
        upd = {k: v["update"] for k, v in res.items()}
        # Weight by sample count, matching FedAvg, so the control arm differs
        # from DLTF only in the trust weighting and not in the aggregation
        # rule. fl/client.py unpacks (update, num_samples) but the key it
        # exposes is not fixed across versions, so probe rather than assume:
        # silently falling back to equal weights would change what the control
        # arm measures without saying so.
        w = {}
        for k, v in res.items():
            n = None
            for key in ("num_samples", "n_samples", "samples", "num_examples"):
                if key in v:
                    n = v[key]
                    break
            if n is None and not PlainServer._warned:
                print("    NOTE: no sample-count key in the train() result "
                      "(saw %s); falling back to equal weights."
                      % sorted(v.keys()))
                PlainServer._warned = True
            w[k] = float(n if n is not None else 1.0)
        agg = self._agg(upd, w)
        self.global_params = [p + u for p, u in zip(self.global_params, agg)]
        # not required here (this script drives its own round loop rather than
        # eval.scenarios.run_rounds) but kept identical to the other control
        # arms so the three cannot drift apart.
        return {"round": rid, "events": {}, "weights": w,
                "probation_decisions": [], "aggregated": True}


# --------------------------------------------------------------------------

def run_arm(defense, attack, seed, args, loaders, val_loader, device):
    torch.manual_seed(seed)
    initial = MNISTModel().get_parameters()

    n_att = args.attackers if attack == "poison" else 0
    ca_key, ca_cert = generate_test_ca()

    if defense == "dltf":
        server = FederatedServer(initial_params=initial,
                                 ca_bundle_pem=ca_bundle_pem(ca_cert),
                                 shadow_eval_fn=lambda p: evaluate(
                                     p, val_loader, device))
    else:
        server = PlainServer(initial)

    handles, attackers = [], []
    for c in range(args.clients):
        flip = c < n_att
        label = ("a%d" % c) if flip else ("h%d" % c)
        loader = loaders[c]

        is_att = c < n_att
        flip_this = is_att and args.attack_type == "flip"
        scale_this = args.scale if (is_att and args.attack_type == "scale") else 1.0

        def trainer(rid, flat, _l=loader, _f=flip_this, _s=scale_this):
            return local_update(flat, _l, args.epochs, args.lr, _f,
                                device, args.max_batches, scale=_s)

        cert = None
        if flip:
            cert, _ = issue_ek_cert(ca_key, ca_cert, label)
            attackers.append(label)
        handles.append(make_handle(label, trainer, ek_cert_der=cert))

    for h in handles:
        server.enroll(h)

    rows = []
    for rid in range(args.rounds):
        t0 = time.perf_counter()
        server.run_round(rid, handles)
        acc = evaluate(server.global_params, val_loader, device)
        banned = 0
        if server.rep is not None:
            for a in attackers:
                d = server.rep._dev.get(a)
                if d is not None and "BAN" in str(getattr(d, "status", "")).upper():
                    banned += 1
        rows.append([defense, attack, seed, rid, round(acc, 4), banned,
                     round((time.perf_counter() - t0), 2)])
        print("    %-6s %-7s seed=%d round %2d  acc=%.4f  banned=%d  (%.1fs)"
              % (defense, attack, seed, rid, acc, banned,
                 time.perf_counter() - t0))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=8)
    ap.add_argument("--attackers", type=int, default=2)
    ap.add_argument("--rounds", type=int, default=15)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--epochs", type=int, default=1)
    ap.add_argument("--lr", type=float, default=0.05)
    ap.add_argument("--attack-type", choices=("flip", "scale"), default="flip",
                    help="flip: label flipping y -> 9-y, caught by the cosine "
                         "stage. scale: honest training with an inflated "
                         "update, caught by the norm stage.")
    ap.add_argument("--scale", type=float, default=10.0,
                    help="multiplier for --attack-type scale")
    ap.add_argument("--max-batches", type=int, default=0,
                    help="cap batches per epoch; 0 = whole shard")
    ap.add_argument("--quick", action="store_true",
                    help="tiny smoke run to validate the pipeline")
    ap.add_argument("--data", default="data")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    if args.quick:
        args.clients, args.attackers = 4, 1
        args.rounds, args.seeds, args.max_batches = 3, 1, 10

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("device:", device)

    train_ds, _ = load_mnist(args.data)
    loaders, val_loader = build_client_loaders(train_ds, args.clients,
                                               seed=0)
    print("clients=%d attackers=%d rounds=%d seeds=%d attack=%s%s"
          % (args.clients, args.attackers, args.rounds, args.seeds,
             args.attack_type,
             (" x%g" % args.scale) if args.attack_type == "scale" else ""))

    rows = []
    for attack in ("none", "poison"):
        for defense in ("plain", "dltf"):
            for seed in range(args.seeds):
                rows.extend(run_arm(defense, attack, seed, args,
                                    loaders, val_loader, device))

    suffix = "" if args.attack_type == "flip" else "_" + args.attack_type
    _write(os.path.join(args.out, "real_mnist%s.csv" % suffix),
           ["defense", "attack", "seed", "round", "accuracy", "attackers_banned",
            "round_s"], rows)

    # Final-round accuracy is NOT a safe summary here. Under label-flip
    # poisoning the unprotected model oscillates every round, so the final
    # value depends on the parity of the stopping round rather than on the
    # system. Average the tail instead, and report the amplitude, which is the
    # more informative quantity: it says whether the federation converges at
    # all. See eval/summarize_real_mnist.py for the full breakdown.
    k = min(5, args.rounds)
    tail = {}
    for defense, attack, seed, rid, acc, nb, _t in rows:
        if rid >= args.rounds - k:
            tail.setdefault((attack, defense), []).append(acc)

    print("\n%-8s %-8s %12s %12s" % ("attack", "defense",
                                     "tail mean", "tail min"))
    print("-" * 46)
    for attack in ("none", "poison"):
        for defense in ("plain", "dltf"):
            v = tail.get((attack, defense))
            if v:
                print("%-8s %-8s %12.4f %12.4f"
                      % (attack, defense, st.mean(v), min(v)))

    off, on = tail.get(("poison", "plain")), tail.get(("poison", "dltf"))
    if off and on:
        print("\nmargin under poisoning on REAL MNIST (mean of last %d rounds):"
              " %+.4f" % (k, st.mean(on) - st.mean(off)))
        print("oscillation without the layer: %.4f, with it: %.4f"
              % (max(off) - min(off), max(on) - min(on)))
        print("\nRun  python -m eval.summarize_real_mnist --file %s  for the"
              % os.path.basename(os.path.join(args.out,
                                              "real_mnist%s.csv" % suffix)))
        print("per-seed")
        print("breakdown, the first-ban rounds, and the comparison against the")
        print("synthetic substrate.")


if __name__ == "__main__":
    main()
