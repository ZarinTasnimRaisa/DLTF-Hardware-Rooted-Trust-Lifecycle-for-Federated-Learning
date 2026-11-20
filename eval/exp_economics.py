"""
eval/exp_economics.py  --  what a federation actually costs, in money.

WHY
-----------------------------------------------------------------------------
The paper reports 58,281 + 38,818n gas per round and stops there. Gas is the
right unit for a claim about the contract, and the wrong unit for the question
a practitioner asks, which is whether running this is affordable. No system in
the related work answers it.

It also lets the attacker-cost result be stated in one currency on both sides.
Table 3 prices an attacker in certified TPMs; this prices the sanctions those
TPMs are bound by. A design whose enforcement costs more than the identity it
enforces against is not a deterrent, and that comparison cannot be made while
one side is in gas and the other in silicon.

HOW TO READ THE OUTPUT, AND WHAT IT IS NOT
-----------------------------------------------------------------------------
Gas is a property of the bytecode. Price is a property of a market on a day.
So this script separates them completely: it never bakes a price into a gas
number, it prints the price and the date it was taken beside every figure, and
it refuses to quote a currency total without them.

Prices are supplied, never fetched. A number scraped at run time makes the
result irreproducible and the paper unciteable six months later. Pass
--gas-price and --token-price explicitly, record the date, and say both in the
caption.

    # measured gas, priced at a stated market
    PYTHONPATH=. python3 -m eval.exp_economics \\
        --gas-price 30 --token-price 0.42 --token MATIC \\
        --price-date 2026-08-31

    # measure gas against a live deployment first, then price it
    PYTHONPATH=. python3 -m eval.exp_economics --rpc $DLTF_CHAIN_RPC \\
        --address 0x... --measure --gas-price 30 --token-price 0.42

Output: results/chain/economics.csv and a table for the paper.
"""
import argparse
import csv
import os
import sys

# The paper's fit. Kept as constants so --measure can CHECK them rather than
# quietly replacing them: a live chain that disagrees with the published model
# is a finding, not an update.
PAPER_INTERCEPT = 58_281
PAPER_SLOPE = 38_818
PAPER_DEPLOY = 2_085_425

GWEI = 10 ** 9


def round_gas(n, intercept=PAPER_INTERCEPT, slope=PAPER_SLOPE):
    return intercept + slope * n


def cost(gas, gas_price_gwei, token_price):
    """gas x price -> currency. Two multiplications, stated explicitly
    because the whole point is that the reader can redo them."""
    native = gas * gas_price_gwei * GWEI / 1e18
    return native, native * token_price


# ---- optional live measurement ---------------------------------------------

def measure(rpc, address, deploy_block, clients):
    """Measure a steady-state round against a live deployment.

    Returns (intercept, slope, observations). Refits from real receipts rather
    than trusting the published model, and reports the disagreement.
    """
    from chain.evm import EvmBackend
    from chain.fixedpoint import SeverityFP, TierFP
    import hashlib

    b = EvmBackend.connect(rpc, address, writer=b"econ",
                           deploy_block=deploy_block)
    if b.signer is None:
        raise SystemExit("set DLTF_CHAIN_PRIVKEY: measuring costs real "
                         "transactions and needs a signing key")

    obs = []
    for n in clients:
        b.gas_reset()
        labels = [f"e{n}_{i}" for i in range(n)]
        for l in labels:
            b.register(b"econ", l, TierFP.HARDWARE,
                       hashlib.sha256(l.encode()).digest())
        # warm round first: a first write to a zero slot costs an order of
        # magnitude more than an update to a warm one, so a cold round is not
        # the steady state the model describes.
        base = b.last_round() + 1
        for rid in (base, base + 1):
            b.gas_reset()
            for l in labels:
                b.classify(b"econ", rid, l, SeverityFP.NEUTRAL)
            b.round_summary(b"econ", rid,
                            hashlib.sha256("|".join(labels).encode()).digest(),
                            True, b"\x00" * 32)
            last = b.gas_total()
        obs.append((n, last))
        print(f"  measured n={n}: {last:,} gas "
              f"(model says {round_gas(n):,}, "
              f"delta {last - round_gas(n):+,})")

    if len(obs) >= 2:
        xs = [o[0] for o in obs]
        ys = [o[1] for o in obs]
        mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
        denom = sum((x - mx) ** 2 for x in xs)
        slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom
        intercept = my - slope * mx
    else:
        intercept, slope = PAPER_INTERCEPT, PAPER_SLOPE

    # Real fee actually paid, which gas alone cannot tell you.
    if b.fee_log:
        prices = [p for _, _, p, _ in b.fee_log if p]
        if prices:
            print(f"  effective gas price observed: "
                  f"{min(prices) / GWEI:.2f}-{max(prices) / GWEI:.2f} gwei")
    return intercept, slope, obs


# ---- main ------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gas-price", type=float, required=True,
                    help="gwei. State it in the caption; it is a market "
                         "condition, not a property of the system.")
    ap.add_argument("--token-price", type=float, required=True,
                    help="native token price in the quote currency")
    ap.add_argument("--token", default="MATIC")
    ap.add_argument("--currency", default="USD")
    ap.add_argument("--price-date", required=True,
                    help="the date both prices were taken (YYYY-MM-DD). "
                         "Required: a currency figure without a date is not "
                         "reproducible and should not go in a paper.")
    ap.add_argument("--clients", type=int, nargs="+", default=[10, 20, 50])
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--tpm-price", type=float, default=15.0,
                    help="cost of one certified TPM module, for the "
                         "attacker-cost comparison")
    ap.add_argument("--measure", action="store_true",
                    help="refit the model against a live deployment instead "
                         "of using the published constants")
    ap.add_argument("--rpc", default=os.environ.get("DLTF_CHAIN_RPC"))
    ap.add_argument("--address",
                    default=os.environ.get("DLTF_CONTRACT_ADDRESS"))
    ap.add_argument("--deploy-block", type=int,
                    default=int(os.environ.get("DLTF_DEPLOY_BLOCK", 0) or 0))
    ap.add_argument("--out", default="results/chain")
    args = ap.parse_args(argv)

    intercept, slope = PAPER_INTERCEPT, PAPER_SLOPE
    source = "published fit (Table 4)"
    if args.measure:
        if not (args.rpc and args.address):
            ap.error("--measure needs --rpc and --address")
        print("measuring against the live deployment...")
        intercept, slope, _ = measure(args.rpc, args.address,
                                      args.deploy_block, args.clients)
        source = f"refit on {args.rpc}"
        print(f"  refit: {intercept:,.0f} + {slope:,.0f}n "
              f"(published: {PAPER_INTERCEPT:,} + {PAPER_SLOPE:,}n)")
        drift = abs(slope - PAPER_SLOPE) / PAPER_SLOPE
        if drift > 0.01:
            print(f"  \u26a0 the live slope differs from the published one by "
                  f"{drift * 100:.1f}%. Gas is deterministic given identical "
                  f"bytecode and calldata, so a difference this size means "
                  f"one of those differs -- check the compiler settings and "
                  f"the device-label lengths before reporting either number.")

    gp, tp = args.gas_price, args.token_price
    print()
    print("=" * 74)
    print(f"ON-CHAIN COST IN CURRENCY   ({source})")
    print(f"gas model {intercept:,.0f} + {slope:,.0f}n per round")
    print(f"priced at {gp:g} gwei and {args.token} = "
          f"{args.currency} {tp:g}, {args.price_date}")
    print("=" * 74)

    rows = []
    hdr = (f"{'clients':>8} {'gas/round':>12} {'per client':>11} "
           f"{args.token + '/round':>13} {args.currency + '/round':>12} "
           f"{args.currency + '/' + str(args.rounds) + 'rd':>13} "
           f"{args.currency + '/client':>11}")
    print(hdr)
    for n in args.clients:
        g = round_gas(n, intercept, slope)
        native, fiat = cost(g, gp, tp)
        fed_native, fed_fiat = cost(g * args.rounds, gp, tp)
        print(f"{n:>8} {g:>12,.0f} {g / n:>11,.0f} {native:>13.6f} "
              f"{fiat:>12.4f} {fed_fiat:>13.4f} {fed_fiat / n:>11.4f}")
        rows.append([n, round(g), round(g / n, 1), f"{native:.8f}",
                     f"{fiat:.6f}", f"{fed_fiat:.6f}",
                     f"{fed_fiat / n:.6f}"])

    dep_native, dep_fiat = cost(PAPER_DEPLOY, gp, tp)
    print()
    print(f"one-off deployment: {PAPER_DEPLOY:,} gas = "
          f"{args.currency} {dep_fiat:.4f}")

    # --- the comparison the paper cannot currently make --------------------
    print()
    print("-" * 74)
    print("ATTACKER COST vs ENFORCEMENT COST")
    print("-" * 74)
    n_ref = args.clients[len(args.clients) // 2]
    _, fed_fiat = cost(round_gas(n_ref, intercept, slope) * args.rounds, gp, tp)
    # Table 3: a HARDWARE attacker consumes 8.0 identities over 30 rounds.
    ids = 8.0
    attacker = ids * args.tpm_price
    print(f"  running a {args.rounds}-round federation at n={n_ref}: "
          f"{args.currency} {fed_fiat:.4f}")
    print(f"  a HARDWARE attacker's {ids:g} certified modules "
          f"(Table 3) at {args.currency} {args.tpm_price:g} each: "
          f"{args.currency} {attacker:.2f}")
    print(f"  ratio: the attack costs {attacker / max(fed_fiat, 1e-12):,.0f}x "
          f"what it costs to run the ledger that sanctions it")
    print()
    print("  That ratio is the argument, and it is the one number that makes")
    print("  the design's economics legible: the sanction is durable because")
    print("  the identity is expensive, while the record making it durable is")
    print("  nearly free. It also bounds the honest claim -- the ratio moves")
    print("  with the gas price and with the price of a TPM, so it is a")
    print("  statement about a market on a date, not a constant of the")
    print("  design.")
    print("-" * 74)

    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, "economics.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["# gas model", f"{intercept:.0f} + {slope:.0f}n",
                    "source", source])
        w.writerow(["# gas_price_gwei", gp, "token", args.token,
                    "token_price", tp, "currency", args.currency,
                    "price_date", args.price_date])
        w.writerow(["clients", "gas_per_round", "gas_per_client",
                    f"{args.token}_per_round", f"{args.currency}_per_round",
                    f"{args.currency}_per_{args.rounds}_rounds",
                    f"{args.currency}_per_client"])
        w.writerows(rows)
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
