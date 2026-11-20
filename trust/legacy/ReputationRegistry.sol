// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ReputationRegistry (v3) — on-chain PUBLIC RECORD of the off-chain engine.
 *
 * ARCHITECTURE (v3 design decision): the chain STORES reputation values;
 * it does NOT compute them. trust/reputation.py is the sole reputation
 * computer; after judging each event the FL server pushes the resulting
 * (trust, weight, status) here, together with the evidence state (s, f) in
 * the event log. The contract performs NO reputation arithmetic — no
 * priors, no evidence weights, no forgetting, no thresholds, no gate.
 * Change the engine's parameters and NOTHING here needs redeploying.
 *
 * WHAT REMAINS ON-CHAIN ARE RULES, NOT ARITHMETIC — the guarantees worth
 * making tamper-evident:
 *   R1 single writer      only the FL server address may write; reads are
 *                         public. Judgments stay with the server; memory
 *                         becomes public and tamper-evident.
 *   R2 O2 anti-whitewash  bans bind to the EK hash IN THE CONTRACT: a
 *                         banned hardware identity re-registers as Banned,
 *                         enforced here, not by server goodwill.
 *   R3 ban terminality    a Banned device is terminal: further pushes are
 *                         no-ops; a banned EK can never be un-banned.
 *   R4 validity bounds    pushed values are range-checked (trust, weight
 *                         in [0, 1e6]; severity <= 4) — comparisons, not
 *                         computation.
 *
 * AUDITABILITY: every push emits the judged severity and the engine's
 * evidence state (s, f) scaled by 1e6. Anyone can recompute
 *     trust = (1e6 + s) * 1e6 / (2e6 + s + f)
 * off-chain from the event log and verify the server's pushed trust — the
 * canonical Beta(1,1) opinion (v3, uniform across tiers) is checkable
 * without the contract ever doing the division.
 *
 * DESIGN CONTRACT WITH THE PYTHON ENGINE
 *   - All real numbers are fixed-point integers scaled by 1e6 (SCALE).
 *     trust 0.75 == 750000, truncated (floored) at the pusher.
 *   - Parity is proven by test_parity.py: the golden scenarios are replayed
 *     through the engine and pushed here round by round; after every event
 *     the chain record must read back the engine's status exactly and its
 *     trust/weight within quantization (~1e-6 / ~6e-5).
 *   - No loops in single-device paths; the batch walks its calldata only.
 */
contract ReputationRegistry {
    // ---------------------------------------------------------- constants
    uint256 private constant SCALE = 1e6;

    // Severity encoding (bridge maps Python strings to these) — recorded
    // in the audit log only; the contract takes no decision from it:
    // 0 POSITIVE, 1 NEUTRAL, 2 MINOR, 3 MAJOR, 4 CRITICAL
    uint8 public constant SEV_CRITICAL = 4;

    // v3 canonical uniform start (Beta(1,1) => trust 0.5). A recorded
    // initial VALUE, not a computation.
    uint256 public constant INITIAL_TRUST = 500000;

    enum Status { Active, Probation, Banned }
    // Tier: 0 = HARDWARE, 1 = TPM_RESIDENT, 2 = SOFTWARE
    //       (Python Tier enum value minus 1; the bridge converts).
    //       Recorded for the audit trail; the contract takes no decision
    //       from it — tier policy (discount vector, rehab, gate) lives
    //       entirely in the off-chain engine.

    // ------------------------------------------------------------- state
    struct Device {
        uint8   tier;
        bytes32 ekHash;
        uint256 trust;      // scaled by 1e6, pushed by the server
        uint256 weight;     // scaled by 1e6, pushed by the server
        Status  status;
        uint64  seq;        // number of pushes recorded (audit ordering)
        bool    exists;
    }

    address public immutable server;
    mapping(bytes32 => Device) private devices;   // deviceId = keccak256(name)
    mapping(bytes32 => bool)   public bannedEk;   // R2: bans bind to the EK

    // -------------------------------------------------------------- audit
    event DeviceRegistered(bytes32 indexed id, uint8 tier, bytes32 ekHash,
                           Status status, uint256 trust, uint256 weight);
    event ReputationPushed(bytes32 indexed id, uint8 severity, uint256 trust,
                           uint256 weight, Status status, uint256 s,
                           uint256 f, uint64 seq);
    event StatusChanged(bytes32 indexed id, Status from, Status to);
    event Reinstated(bytes32 indexed id, uint32 trialRounds, uint256 trust,
                     uint256 weight);
    event EkBanned(bytes32 indexed ekHash);

    modifier onlyServer() {
        require(msg.sender == server, "not the FL server");
        _;
    }

    constructor() {
        server = msg.sender;
    }

    // --------------------------------------------------------- lifecycle
    /// The server registers a device with the initial weight it computed
    /// off-chain (D[tier] * 0.5). Trust starts at the canonical 0.5 for
    /// every tier (v3 uniform prior). R2: a banned EK is re-banned here,
    /// by the contract, regardless of what the server pushes later.
    function register(bytes32 id, uint8 tier, bytes32 ekHash,
                      uint256 initialWeight)
        external onlyServer returns (Status)
    {
        require(tier <= 2, "bad tier");
        require(!devices[id].exists, "id exists");
        require(initialWeight <= SCALE, "weight out of range");
        bool ekBanned = bannedEk[ekHash];                             // R2
        Status st = ekBanned ? Status.Banned : Status.Active;
        devices[id] = Device(tier, ekHash, INITIAL_TRUST,
                             ekBanned ? 0 : initialWeight, st, 0, true);
        emit DeviceRegistered(id, tier, ekHash, st, INITIAL_TRUST,
                              devices[id].weight);
        return st;
    }

    /// One judged event: the server pushes the engine's post-event state.
    /// severity, s, f go to the audit log; trust/weight/status are stored.
    /// R3: pushes to a Banned device are no-ops (mirrors the engine, where
    /// record_event on a banned device returns immediately).
    function pushReputation(bytes32 id, uint8 severity, uint256 trust,
                            uint256 weight, Status status,
                            uint256 s, uint256 f)
        public onlyServer returns (Status)
    {
        Device storage d = devices[id];
        require(d.exists, "unknown device");
        if (d.status == Status.Banned) return Status.Banned;          // R3
        require(severity <= SEV_CRITICAL, "bad severity");            // R4
        require(trust <= SCALE && weight <= SCALE, "value out of range");

        d.trust = trust;
        d.weight = status == Status.Banned ? 0 : weight;
        _setStatus(d, id, status);
        if (status == Status.Banned && d.ekHash != bytes32(0)) {
            if (!bannedEk[d.ekHash]) {
                bannedEk[d.ekHash] = true;                            // R2
                emit EkBanned(d.ekHash);
            }
        }
        d.seq += 1;
        emit ReputationPushed(id, severity, d.trust, d.weight, d.status,
                              s, f, d.seq);
        return d.status;
    }

    /// Batch variant: one transaction per FL round instead of one per event.
    struct Push {
        bytes32 id;
        uint8   severity;
        uint256 trust;
        uint256 weight;
        Status  status;
        uint256 s;
        uint256 f;
    }

    function pushReputations(Push[] calldata items) external onlyServer {
        for (uint256 i = 0; i < items.length; i++) {
            pushReputation(items[i].id, items[i].severity, items[i].trust,
                           items[i].weight, items[i].status, items[i].s,
                           items[i].f);
        }
    }

    /// Reinstatement is a distinct audit event. The floor (REINSTATE_T =
    /// 0.75 via the closed form) is computed off-chain by the engine; the
    /// contract only enforces the RULE that reinstatement is a
    /// Probation -> Active move.
    function reinstate(bytes32 id, uint32 trialRounds, uint256 trust,
                       uint256 weight)
        external onlyServer returns (bool)
    {
        Device storage d = devices[id];
        require(d.exists, "unknown device");
        if (d.status != Status.Probation) return false;
        require(trust <= SCALE && weight <= SCALE, "value out of range");
        d.trust = trust;
        d.weight = weight;
        _setStatus(d, id, Status.Active);
        d.seq += 1;
        emit Reinstated(id, trialRounds, trust, weight);
        return true;
    }

    function _setStatus(Device storage d, bytes32 id, Status to) private {
        if (d.status != to) {
            emit StatusChanged(id, d.status, to);
            d.status = to;
        }
    }

    // --------------------------------------------------------------- views
    function getTrust(bytes32 id) external view returns (uint256) {
        require(devices[id].exists, "unknown device");
        return devices[id].trust;
    }

    function getStatus(bytes32 id) external view returns (Status) {
        require(devices[id].exists, "unknown device");
        return devices[id].status;
    }

    function getWeight(bytes32 id) external view returns (uint256) {
        Device storage d = devices[id];
        require(d.exists, "unknown device");
        return d.status == Status.Banned ? 0 : d.weight;
    }

    function getDevice(bytes32 id) external view returns (
        uint8 tier, bytes32 ekHash, uint256 trust, uint256 weight,
        Status status, uint64 seq)
    {
        Device storage d = devices[id];
        require(d.exists, "unknown device");
        return (d.tier, d.ekHash, d.trust, d.weight, d.status, d.seq);
    }

    function isEkBanned(bytes32 ekHash) external view returns (bool) {
        return bannedEk[ekHash];
    }
}
