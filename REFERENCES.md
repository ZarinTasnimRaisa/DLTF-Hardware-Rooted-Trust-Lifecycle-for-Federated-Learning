# DLTF — References

IEEE style. VERIFY every entry against Google Scholar / the publisher before
submission: confirm exact title, authors, venue, year, volume/pages, and DOI.
Some entries below are reconstructed from memory of well-known works and may have
small errors. Each reference is annotated with where it is used in the thesis.

====================================================================
A. TRUSTED COMPUTING / TPM HARDWARE IDENTITY  (Chapter: Identity layer, tpm/)
====================================================================

[1] Trusted Computing Group, "Trusted Platform Module Library Specification,
    Family 2.0, Level 00, Revision 1.59," TCG, 2019.
    -> Basis for EK, AIK, MakeCredential/ActivateCredential, EK certificate profile.

[2] Trusted Computing Group, "TCG EK Credential Profile for TPM Family 2.0,"
    Version 2.x, TCG.
    -> EK certificate NV indices and the EK-cert-as-silicon-proof argument.

[3] W. Arthur, D. Challener, and K. Goldman, "A Practical Guide to TPM 2.0,"
    Apress (Open Access), 2015.
    -> Reference for the credential-activation workflow used in tpm/client.py.

====================================================================
B. REPUTATION AND TRUST MODELS  (Chapter: Trust layer, reputation*.py)
====================================================================

[4] A. Josang and R. Ismail, "The Beta Reputation System," in Proc. 15th Bled
    Electronic Commerce Conference, 2002.
    -> Foundation of the v3 engine's subjective-logic form (Beta posterior,
        probability expectation E = b + a·u). NOTE: the old additive/beta
        two-engine ablation is retired; there is ONE engine (trust/reputation.py).

[5] S. D. Kamvar, M. T. Schlosser, and H. Garcia-Molina, "The EigenTrust
    Algorithm for Reputation Management in P2P Networks," in Proc. 12th Int. World
    Wide Web Conf. (WWW), 2003.
    -> Score-based P2P trust; contrasted as identity-free (cannot resist whitewashing).

[6] L. Xiong and L. Liu, "PeerTrust: Supporting Reputation-Based Trust for
    Peer-to-Peer Electronic Communities," IEEE Trans. Knowledge and Data
    Engineering, vol. 16, no. 7, pp. 843-857, 2004.
    -> Score + threshold reputation structure (the additive engine's lineage).

[7] L. Mui, M. Mohtashemi, and A. Halberstadt, "A Computational Model of Trust
    and Reputation," in Proc. 35th Hawaii Int. Conf. System Sciences (HICSS), 2002.
    -> Bayesian trust with informative priors; basis for hardware-informed priors.

[8] W. T. L. Teacy, J. Patel, N. R. Jennings, and M. Luck, "TRAVOS: Trust and
    Reputation in the Context of Inaccurate Information Sources," Autonomous Agents
    and Multi-Agent Systems, vol. 12, no. 2, pp. 183-198, 2006.
    -> Confidence-aware Bayesian reputation; future-work direction for the beta engine.

[9] S. Buchegger and J.-Y. Le Boudec, "A Robust Reputation System for Peer-to-Peer
    and Mobile Ad-hoc Networks," in Proc. P2PEcon, 2004.
    -> Reputation fading / forgetting; basis for tier-coupled forgetting.

[10] Y. Sun, W. Yu, Z. Han, and K. J. R. Liu, "Information Theoretic Framework of
     Trust Modeling and Evaluation for Ad Hoc Networks," IEEE J. Selected Areas in
     Communications, vol. 24, no. 2, pp. 305-317, 2006.
     -> Asymmetric trust dynamics (trust lost faster than gained).

====================================================================
C. DESIGN PRINCIPLES / THEORY  (Chapter: Motivation, constants rationale)
====================================================================

[11] E. Friedman and P. Resnick, "The Social Cost of Cheap Pseudonyms," J.
     Economics & Management Strategy, vol. 10, no. 2, pp. 173-199, 2001.
     -> THE theoretical backbone: sanctions are meaningless when identities are free.

[12] E. Ostrom, "Governing the Commons: The Evolution of Institutions for
     Collective Action," Cambridge University Press, 1990.
     -> Graduated-sanctions principle behind the strike/probation/ban ladder.

[13] P. Slovic, "Perceived Risk, Trust, and Democracy," Risk Analysis, vol. 13,
     no. 6, pp. 675-682, 1993.
     -> Trust-asymmetry DIRECTION only. Does NOT justify a rate ratio: v3 has
        FORGET = GAMMA = 0.90 (one decay primitive); the asymmetry comes from
        the FORGIVE_AFTER gate, not a 5:1 damage-to-repair ratio (retired).

[14] S. Buchegger and J.-Y. Le Boudec, "Performance Analysis of the CONFIDANT
     Protocol," in Proc. ACM MobiHoc, 2002.
     -> Severity-weighted, asymmetric misbehavior penalties.

====================================================================
D. FEDERATED LEARNING AND POISONING DEFENSES  (Chapter: FL + detection, fl/, filter.py)
====================================================================

[15] H. B. McMahan, E. Moore, D. Ramage, S. Hampson, and B. Aguera y Arcas,
     "Communication-Efficient Learning of Deep Networks from Decentralized Data,"
     in Proc. 20th Int. Conf. Artificial Intelligence and Statistics (AISTATS), 2017.
     -> FedAvg; the baseline aggregator and the undefended control arm.

[16] P. Blanchard, E. M. El Mhamdi, R. Guerraoui, and J. Stainer, "Machine
     Learning with Adversaries: Byzantine Tolerant Gradient Descent," in Advances
     in Neural Information Processing Systems (NeurIPS), 2017.
     -> Krum; robust aggregation and the cosine-deviation idea in filter.py.

[17] D. Yin, Y. Chen, R. Kannan, and P. Bartlett, "Byzantine-Robust Distributed
     Learning: Towards Optimal Statistical Rates," in Proc. 35th Int. Conf. Machine
     Learning (ICML), 2018.
     -> Trimmed-mean aggregation in fl/aggregator.py.

[18] C. Fung, C. J. M. Yoon, and I. Beschastnikh, "The Limitations of Federated
     Learning in Sybil Settings," in Proc. 23rd Int. Symp. Research in Attacks,
     Intrusions and Defenses (RAID), 2020.
     -> FoolsGold; basis for the sustained pairwise-similarity Sybil detector
        (cite as "FoolsGold-style"; the implementation here is a simplified variant).

[19] M. Fang, X. Cao, J. Jia, and N. Z. Gong, "Local Model Poisoning Attacks to
     Byzantine-Robust Federated Learning," in Proc. 29th USENIX Security
     Symposium, 2020.
     -> Targeted poisoning threat model addressed by stage-2 detection.

[20] X. Cao, M. Fang, J. Liu, and N. Z. Gong, "FLTrust: Byzantine-Robust
     Federated Learning via Trust Bootstrapping," in Proc. Network and Distributed
     System Security Symposium (NDSS), 2021.
     -> Server-side trust scoring; contrasted as having no persistence or sanctions.

====================================================================
E. RELATED FL-SECURITY / RECOVERY SYSTEMS  (Chapter: Related work, novelty contrast)
====================================================================

[21] J. Kang, Z. Xiong, D. Niyato, S. Xie, and J. Zhang, "Incentive Mechanism for
     Reliable Federated Learning: A Joint Optimization Approach to Combining
     Reputation and Contract Theory," IEEE Internet of Things Journal, vol. 6,
     no. 6, pp. 10700-10714, 2019.
     -> Reputation-weighted FL client selection; closest prior reputation-in-FL work.

[22] J. Kang, Z. Xiong, D. Niyato, Y. Zou, Y. Zhang, and M. Guizani, "Reliable
     Federated Learning for Mobile Networks," IEEE Wireless Communications,
     vol. 27, no. 2, pp. 72-80, 2020.
     -> Blockchain-stored beta-reputation for FL; contrasted (identities still cheap).

[23] X. Cao, J. Jia, Z. Zhang, and N. Z. Gong, "FedRecover: Recovering from
     Poisoning Attacks in Federated Learning using Historical Information," in
     Proc. IEEE Symposium on Security and Privacy (S&P), 2023.
     -> "Recovery" in FL = model rollback; contrasted with DLTF client rehabilitation.

[24] J. Domingo-Ferrer, A. Blanco-Justicia, et al., "Co-Utile Peer-to-Peer
     Decentralized Computing" / co-utility reputation for federated learning.
     -> Newcomers start at reputation zero; cannot distinguish whitewashers from
        genuine newcomers (DLTF's hardware identity can). VERIFY exact citation.

====================================================================
F. TOOLS AND LIBRARIES  (software actually used)
====================================================================

[25] tpm2-software community, "tpm2-tools: The TPM2.0 tools," GitHub project.
[26] tpm2-software community, "swtpm: Software TPM Emulator," GitHub project.
[27] Python Cryptographic Authority, "cryptography" library (X.509 verification).
[28] C. R. Harris et al., "Array Programming with NumPy," Nature, vol. 585, 2020.
[29] A. Paszke et al., "PyTorch: An Imperative Style, High-Performance Deep
     Learning Library," in Advances in Neural Information Processing Systems
     (NeurIPS), 2019.
[30] Y. LeCun, C. Cortes, and C. J. C. Burges, "The MNIST Database of Handwritten
     Digits," 1998.
[31] Tailscale Inc., "Tailscale: A WireGuard-based mesh VPN," product documentation.
     -> Internet deployment transport (Section: deployment).

====================================================================
NOTES FOR THE WRITE-UP
====================================================================
- Cite [11] Friedman & Resnick prominently in the motivation; it is the single
  strongest justification for the whole hardware-identity premise.
- For the detector, always write "FoolsGold-style" [18] and "Krum-style" [16];
  do not claim the exact algorithms.
- For "recovery" be explicit: [23] FedRecover = model rollback, ORTHOGONAL to
  DLTF's client rehabilitation; this distinction is part of the novelty argument.
- [4] Josang & Ismail backs the beta engine; [11]-[14] back the constants rationale.
- Verify [24] Co-Utility carefully; it is used as a direct novelty contrast, so the
  exact paper and claim must be correct.

====================================================================
G. MISSING / TO VERIFY (flagged by MASTER_CONTEXT §9 — add before submission)
====================================================================
Do NOT fabricate entries: look each up, verify venue/year/pages, then add.

- Wang 2022 — TPM + blockchain oracle FL. Uses TPM for update INTEGRITY, not
  persistent identity binding; DLTF binds identity so bans survive re-join.
- ZTA-FL — arXiv:2512.23809 (Dec 2025). CLOSEST COMPETING WORK. Name it, state
  exactly what it does, identify the precise gap; hedge novelty with "to our
  knowledge".
- Douceur 2002 — "The Sybil Attack". O1 foundation.
- Theil 1950 / Sen 1968 — slope estimators (SLOPE_ESTIMATOR discussion).
- TrustFed (ur Rehman et al., IEEE T-II 2021) — related trust-in-FL framework.
- Sun 2008 / Labraoui 2015 — cited by the parameter justification report
  (docs/history/); reconcile with [10] Sun 2006.
- Kang 2019 VENUE CONFLICT: [21] says IEEE IoT-J 6(6); the parameter report
  cites IEEE TVT 68(3), arXiv:1809.08387. Verify which is correct.
- [24] Domingo-Ferrer — still marked VERIFY.

====================================================================
H. NOVELTY AND PRIOR WORK (merged from contributions_and_prior_work.md,
   corrected to v3 — 2026-11-17)
====================================================================

## Derived from prior work

**Hardware identity machinery.** The enrollment protocol implements standard
TPM 2.0 mechanisms defined by the Trusted Computing Group: the Endorsement Key
(EK) as a device-bound identity, EK certificates as manufacturer-issued proof
of genuine silicon, and the MakeCredential/ActivateCredential exchange as proof
that a client holds an EK inside a real TPM. None of this cryptography is ours;
we apply it.

**Detection.** The gradient filter composes four established techniques: norm
clipping against the median (scaling attacks), cosine deviation from a robust
median reference (targeted poisoning, in the spirit of Krum [16]), sustained
pairwise-similarity detection of colluding clients (a simplified FoolsGold-style
variant [18]), and temporal self-consistency for sleeper agents. Detection is
deliberately not claimed as a contribution.

**Reputation structure.** The score-threshold-status pattern follows P2P trust
systems (EigenTrust [5]; PeerTrust [6]) and reputation-weighted federated
aggregation (Kang [21]). Three design principles are imported: graduated
sanctions (Ostrom [12]), asymmetric trust dynamics — trust lost faster than
regained (Slovic [13], DIRECTION only; CONFIDANT [14]) — and the result that
sanctions are meaningless when pseudonyms are free (Friedman & Resnick [11]),
the theoretical backbone of this work.

**Learning substrate.** FedAvg [15], Krum [16], trimmed-mean [17], a standard
CNN on MNIST [30], and conventional non-IID partitioning are textbook components.

## Novel in this work (to our knowledge — ZTA-FL is the closest prior work)

1. **Tier-coupled sanction policy.** Existing reputation systems apply one
   policy to all clients. DLTF indexes policy on the measured replacement cost
   of the client's identity (hardware-certified, TPM-resident, software).
   **v3 correction:** the tier couples the weight CAP and REHABILITATION
   eligibility only — strikes/thresholds are uniform across tiers (the score
   is identity-blind). The old "entire policy table incl. strikes" phrasing
   overstates current tier-coupling.
2. **Hardware-persistent negative reputation.** Bans bind to the EK hash, so a
   banned device is recognized at re-enrollment regardless of its claimed name
   — and, with the chain layer, bans persist across SERVER RESTART
   (reconciliation from chain events, N23). Prior systems can only make good
   reputation slow to earn; ours makes bad reputation impossible to shed
   without purchasing new certified hardware: whitewashing becomes
   hardware-cost-bound, not free.
3. **A rehabilitation lifecycle.** Sanctioned Tier-1 devices enter probation in
   which only their own updates train an isolated shadow model; reinstatement
   requires a positive accuracy slope over an HMAC-randomized window, with a
   one-shot extension and permanent ban otherwise. "Recovery" in the FL
   literature means rolling back the model ([23] FedRecover — orthogonal);
   client rehabilitation does not previously exist, and it is only safe
   because of contribution 2.
4. **Quantified attacker cost.** v3 measurements (RESULTS_EXPLAINED §4):
   per-identity influence 0.462 weight-rounds at Tier 1 (cost: a physical TPM)
   vs 0.201 at Tier 2 and 0.040 at Tier 3 (free identities); the defence costs
   nothing in the attack-free case (0.691 vs 0.691). [The old ~0.91/~0.02
   figures were v2.1-era and are retired.]
5. **Verifiable enforcement (chain layer).** The ban ledger is checkable by a
   party that does not trust the server: the contract REJECTS illegal
   transitions by EVM revert (not merely records them), and an independent
   verifier catches silent state tampering (TAMPER-2). A commitment layer
   prevents the server from fabricating updates attributed to clients.

The contribution is therefore a systems composition: known identity primitives
and known detectors, joined by a novel sanction-and-rehabilitation policy rooted
in hardware identity cost, made durable and independently verifiable on chain.
