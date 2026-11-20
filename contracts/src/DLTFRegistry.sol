// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title DLTFRegistry
 * @notice On-chain trust registry for DLTF. Enforces the six rejection rules
 *         that chain/mock.py enforces in Python, using the fixed-point
 *         arithmetic in chain/fixedpoint.py verbatim.
 *
 * INVARIANTS (audit these first):
 *   1. server is immutable; only server may write.
 *   2. Once a device is BANNED, no path returns it to ACTIVE. No exception.
 *   3. A device's tier is immutable after ENROLL.
 *   4. Each round id can be closed by roundSummary at most once, and never
 *      out-of-order.
 *   5. Two device_ids may never claim the same ek_hmac.
 *   6. Every write path either commits the transition or reverts with a
 *      named custom error; there is no silent no-op except the idempotent
 *      register (same device_id, same tier, same ek_hmac).
 *
 * WHAT THIS CONTRACT DOES NOT DO:
 *   - It does not verify the truthfulness of a classification. The server
 *     could emit MAJOR against an honest client. Constraining input
 *     truthfulness requires a different mechanism (multi-party consensus,
 *     ZK update proofs); future work.
 *   - It does not iterate over devices or events. Reconciliation is done
 *     off-chain by replaying emitted events.
 *
 * ARITHMETIC:
 *   Mirrors chain/fixedpoint.py at SCALE = 1e6. Only one truncating op
 *   (`decay(x) = (9*x)/10`), which Solidity's `/` on uint256 implements as
 *   floor -- identical to Python's `//` on non-negative int.
 *
 * STORAGE PACKING (option a per the design):
 *   One 208-bit state per device, held in a single uint256 slot. One warm
 *   SSTORE per device per round.
 */
contract DLTFRegistry {

    // =========================================================================
    //                              CONSTANTS
    // =========================================================================
    // Fixed-point (mirror chain/fixedpoint.py). Every constant exact at 1e6.
    uint64  constant SCALE          = 1_000_000;
    uint64  constant THETA_FP       =   400_000;   // 0.4
    uint64  constant TAU_FP         =   600_000;   // 0.6
    uint64  constant A0_FP          = SCALE;       // Beta(1,1)
    uint64  constant W_PRIOR_FP     = 2_000_000;
    uint64  constant PROBATION_T_FP =   500_000;   // 0.5
    uint64  constant BAN_T_FP       =   300_000;   // 0.3
    uint64  constant REINSTATE_T_FP =   750_000;   // 0.75
    uint16  constant FORGIVE_AFTER          = 2;
    uint16  constant MAJOR_RUN_TO_ESCALATE  = 2;

    // Status
    uint8 constant STATUS_ACTIVE    = 0;
    uint8 constant STATUS_PROBATION = 1;
    uint8 constant STATUS_BANNED    = 2;

    // Tier
    uint8 constant TIER_HARDWARE     = 1;
    uint8 constant TIER_TPM_RESIDENT = 2;
    uint8 constant TIER_SOFTWARE     = 3;

    // Severity (five members; POSITIVE reserved for future positive-evidence source)
    uint8 constant SEV_POSITIVE = 0;
    uint8 constant SEV_NEUTRAL  = 1;
    uint8 constant SEV_MINOR    = 2;
    uint8 constant SEV_MAJOR    = 3;
    uint8 constant SEV_CRITICAL = 4;

    // Probation outcomes
    uint8 constant OUT_REINSTATED    = 0;
    uint8 constant OUT_EXTENDED      = 1;
    uint8 constant OUT_PERMANENT_BAN = 2;

    // Sentinel: no round classified yet (matches DeviceFP.__init__ last_round = -1)
    uint32 constant NO_ROUND = type(uint32).max;

    // =========================================================================
    //                          CUSTOM ERRORS
    //   Names map 1:1 to Reason codes in chain/backend.py (do not rename
    //   without updating the Python port map).
    // =========================================================================
    error UnauthorizedWriter();
    error BanToActive(bytes32 deviceKey);
    error TierMutation(bytes32 deviceKey, uint8 oldTier, uint8 newTier);
    error DuplicateRound(uint256 roundId);
    error StaleRound(uint256 roundId, uint256 lastRound);
    error DeviceUnknown(bytes32 deviceKey);
    error DeviceBanned(bytes32 deviceKey);
    error EkAlreadyRegistered(bytes32 ekHmac);
    error OutcomeInvalid(uint8 outcome);
    error NotOnProbation(bytes32 deviceKey);
    error InvalidSeverity(uint8 severity);
    error InvalidTier(uint8 tier);

    // --- client-commitment errors (see COMMITMENT LAYER below) ---
    error WalletAlreadyBound(address wallet);
    error WalletNotBound(bytes32 deviceKey);
    error NotDeviceWallet(address caller);
    error MissingCommit(bytes32 deviceKey, uint256 roundId);
    error DuplicateCommit(bytes32 deviceKey, uint256 roundId);
    error EmptyCommit();

    // --- batched signed-commitment errors ---
    error BatchLengthMismatch();
    error InvalidSignature(bytes32 deviceKey);
    error SignerNotDeviceWallet(bytes32 deviceKey, address recovered);
    error MalleableSignature();
    error EmptyBatch();

    // =========================================================================
    //                                STORAGE
    // =========================================================================
    address public immutable server;

    // Packed device state. Layout (LSB first):
    //   [0:64]    s           uint64
    //   [64:128]  f           uint64
    //   [128:144] cleanRun    uint16
    //   [144:160] majorRun    uint16
    //   [160:168] status      uint8
    //   [168:176] tier        uint8
    //   [176:208] lastRound   uint32
    //   [208:256] reserved
    mapping(bytes32 => uint256) public devices;

    mapping(bytes32 => bytes32) public deviceEk;      // deviceKey -> ekHmac
    mapping(bytes32 => bool)    public bannedEk;      // ekHmac    -> true if banned
    mapping(bytes32 => bytes32) public ekToDevice;    // ekHmac    -> deviceKey (dup guard)
    mapping(bytes32 => bool)    public rehabUsed;     // deviceKey -> reinstated once already
    mapping(uint256 => bool)    public roundClosed;   // roundId   -> summarised

    uint256 public lastRound;
    bool    public lastRoundSet;

    // =========================================================================
    //                        COMMITMENT LAYER STORAGE
    //
    // Binds each device to exactly one wallet, and records a per-round
    // gradient-hash commitment written BY THE CLIENT (not the server).
    //
    // WHY THE WALLET BINDING IS LOAD-BEARING: without it, a banned physical
    // machine simply commits from a fresh wallet and the commitment proves
    // nothing about identity. The binding is established at enrollment, after
    // the client signs its wallet address with its attestation key and the
    // server verifies that signature against the TPM identity. One wallet,
    // one device, immutable thereafter -- the same shape as tier immutability.
    // =========================================================================
    mapping(bytes32 => address) public deviceWallet;   // deviceKey -> wallet
    mapping(address => bytes32) public walletDevice;   // wallet    -> deviceKey
    // deviceKey -> roundId -> keccak256(serialised gradient)
    mapping(bytes32 => mapping(uint256 => bytes32)) public commitments;

    /// @notice When true, classify() reverts unless the device committed a
    ///         gradient hash for that round. Immutable: a server cannot
    ///         disable the requirement mid-federation.
    bool public immutable requireCommit;

    // =========================================================================
    //                  EIP-712 BATCHED SIGNED COMMITMENTS
    //
    // A commitment does not need a transaction to be binding -- it needs a
    // SIGNATURE. Clients sign (deviceKey, roundId, gradHash) off-chain and
    // hand the signature to the server with the gradient. The server submits
    // every client's signature for a round in ONE transaction.
    //
    // Properties preserved versus per-client transactions:
    //   non-repudiation   an ECDSA signature is unforgeable; the server
    //                     cannot manufacture one for a client that did not
    //                     participate
    //   anti-fabrication  no valid signature => no commitment => classify()
    //                     still reverts with MissingCommit
    //   ban lockout       the recovered address must equal deviceWallet[key],
    //                     and the device must not be BANNED
    //
    // Property NOT preserved: with per-client transactions each commitment is
    // independently timestamped without the server's cooperation. Under
    // batching the server controls submission and could withhold a signature,
    // making a present client appear absent. Mitigation is off-chain: the
    // client retains its signature and can publish it, and anyone can verify
    // it against this contract's domain separator. Detectable, not prevented.
    //
    // Replay protection is structural: the domain separator binds chainId and
    // this contract's address, and the struct binds roundId, so a signature
    // cannot be replayed across rounds, contracts, or chains.
    // =========================================================================
    bytes32 public immutable DOMAIN_SEPARATOR;

    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private constant COMMIT_TYPEHASH = keccak256(
        "GradientCommit(bytes32 deviceKey,uint256 roundId,bytes32 gradHash)");

    /// @dev secp256k1n / 2. Signatures with s above this are the malleable
    ///      counterpart of a valid signature and are rejected.
    uint256 private constant SECP256K1N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    // =========================================================================
    //                                 EVENTS
    // =========================================================================
    event Genesis(bytes32 chainId, uint256 version);
    event Enroll(string deviceId, uint8 tier, bytes32 ekHmac, uint8 status);
    event WhitewashRejected(string deviceId, bytes32 ekHmac);
    event ClassifyEvent(uint256 indexed roundId, string deviceId,
                        uint8 severity, uint8 stage, string reason,
                        uint8 status);
    event Ban(uint256 indexed roundId, string deviceId, bytes32 ekHmac);
    event CommitProof(uint256 indexed roundId, bytes32 indexed deviceKey,
                      bytes32 gradHash, uint8 v, bytes32 r, bytes32 s);
    event ProbationEnter(uint256 indexed roundId, string deviceId);
    event RehabExhausted(uint256 indexed roundId, string deviceId, bytes32 ekHmac);
    event ProbationDecision(uint256 indexed roundId, string deviceId, uint8 outcome);
    event Round(uint256 indexed roundId, bytes32 participantsHash,
                bool aggregated, bytes32 localHead);
    event WalletBound(string deviceId, address wallet);
    event GradientCommitted(uint256 indexed roundId, bytes32 indexed deviceKey,
                            address wallet, bytes32 gradHash);
    event Absent(uint256 indexed roundId, string deviceId);
    event CommitMismatch(uint256 indexed roundId, string deviceId,
                         bytes32 committed, bytes32 received);

    // =========================================================================
    //                                MODIFIER
    // =========================================================================
    modifier onlyServer() {
        if (msg.sender != server) revert UnauthorizedWriter();
        _;
    }

    // =========================================================================
    //                              CONSTRUCTOR
    // =========================================================================
    constructor(address _server, bytes32 chainId, bool _requireCommit) {
        require(_server != address(0), "server=0");
        server = _server;
        requireCommit = _requireCommit;
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            keccak256(bytes("DLTFRegistry")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
        emit Genesis(chainId, 1);
    }

    // =========================================================================
    //                     FIXED-POINT PRIMITIVES (pure)
    //   These MUST match chain/fixedpoint.py bit-for-bit.
    // =========================================================================

    function decay(uint64 x) internal pure returns (uint64) {
        // Floor: identical to Python `(x * 9) // 10` on non-negative int.
        return uint64((uint256(x) * 9) / 10);
    }

    /// @dev trust <= t, by cross-multiplication. Division-free.
    function trustLe(uint64 s, uint64 f, uint64 t) internal pure returns (bool) {
        uint256 lhs = (uint256(A0_FP) + uint256(s)) * uint256(SCALE);
        uint256 rhs = uint256(t) * (uint256(W_PRIOR_FP) + uint256(s) + uint256(f));
        return lhs <= rhs;
    }

    function evidenceDominated(uint64 s, uint64 f) internal pure returns (bool) {
        return (uint256(s) + uint256(f)) > uint256(W_PRIOR_FP);
    }

    /// @dev need_S = 3*(SCALE + f) - SCALE = 3f + 2*SCALE. Exact at r=0.75.
    function reinstateFloor(uint64 f) internal pure returns (uint64) {
        return uint64(3 * uint256(f) + 2 * uint256(SCALE));
    }

    function rehab(uint8 tier) internal pure returns (bool) {
        return tier == TIER_HARDWARE;
    }

    // =========================================================================
    //                            PACK / UNPACK
    // =========================================================================
    struct DeviceState {
        uint64 s;
        uint64 f;
        uint16 cleanRun;
        uint16 majorRun;
        uint8  status;
        uint8  tier;
        uint32 lastRound;
    }

    function pack(DeviceState memory d) internal pure returns (uint256) {
        return uint256(d.s)
            | (uint256(d.f)          <<  64)
            | (uint256(d.cleanRun)   << 128)
            | (uint256(d.majorRun)   << 144)
            | (uint256(d.status)     << 160)
            | (uint256(d.tier)       << 168)
            | (uint256(d.lastRound)  << 176);
    }

    function unpack(uint256 word) internal pure returns (DeviceState memory d) {
        d.s         = uint64(word);
        d.f         = uint64(word >>  64);
        d.cleanRun  = uint16(word >> 128);
        d.majorRun  = uint16(word >> 144);
        d.status    = uint8 (word >> 160);
        d.tier      = uint8 (word >> 168);
        d.lastRound = uint32(word >> 176);
    }

    // =========================================================================
    //                         STATE-TRANSITION RULE
    //   Mirrors FixedEngine._transition. Check order is PINNED:
    //   backstop -> M3 -> probation threshold; each `return`s.
    // =========================================================================
    function _transition(DeviceState memory d) internal pure {
        bool gate = evidenceDominated(d.s, d.f);

        // Backstop
        if (gate && trustLe(d.s, d.f, BAN_T_FP)) {
            if (rehab(d.tier) && d.status == STATUS_ACTIVE) {
                d.status = STATUS_PROBATION;    // D5 due process
            } else {
                d.status = STATUS_BANNED;
            }
            return;
        }

        // M3: consecutive-MAJOR escalation (ungated)
        if (d.majorRun >= MAJOR_RUN_TO_ESCALATE) {
            if (rehab(d.tier)) {
                d.status = STATUS_PROBATION;
            } else {
                d.status = STATUS_BANNED;
            }
            return;
        }

        // Probation threshold (ACTIVE only)
        if (gate && d.status == STATUS_ACTIVE && trustLe(d.s, d.f, PROBATION_T_FP)) {
            if (rehab(d.tier)) {
                d.status = STATUS_PROBATION;
            } else {
                d.status = STATUS_BANNED;
            }
        }
    }

    // =========================================================================
    //                                WRITES
    // =========================================================================

    /**
     * @notice Enroll a device. Emits Enroll on success; emits
     *         WhitewashRejected if ekHmac is already banned (no state change).
     * @dev The idempotent case (same device_id, same tier, same ekHmac) is
     *      accepted silently -- no event, no revert. This matches the mock
     *      backend's behaviour and lets a server retry enrol after a
     *      transient error without corrupting state.
     */
    function register(string calldata deviceId, uint8 tier, bytes32 ekHmac)
        external onlyServer
    {
        if (tier < TIER_HARDWARE || tier > TIER_SOFTWARE) revert InvalidTier(tier);

        // Case A: banned EK -> WHITEWASH, no state change.
        if (bannedEk[ekHmac]) {
            emit WhitewashRejected(deviceId, ekHmac);
            return;
        }

        bytes32 deviceKey = keccak256(bytes(deviceId));
        uint256 existingWord = devices[deviceKey];

        if (existingWord != 0) {
            DeviceState memory existing = unpack(existingWord);
            // Tier immutability check FIRST -- most specific error.
            if (existing.tier != tier) {
                revert TierMutation(deviceKey, existing.tier, tier);
            }
            // BANNED -> ACTIVE attempt via re-enrol.
            if (existing.status == STATUS_BANNED) {
                revert BanToActive(deviceKey);
            }
            // Same device, same EK: idempotent no-op.
            if (deviceEk[deviceKey] == ekHmac) {
                return;
            }
            // Different EK for same device: reject.
            revert EkAlreadyRegistered(ekHmac);
        }

        // Case C: EK already claimed by another device.
        if (ekToDevice[ekHmac] != bytes32(0)) {
            revert EkAlreadyRegistered(ekHmac);
        }

        // Case D: fresh registration.
        DeviceState memory d;
        d.tier      = tier;
        d.status    = STATUS_ACTIVE;
        d.lastRound = NO_ROUND;
        devices[deviceKey]  = pack(d);
        deviceEk[deviceKey] = ekHmac;
        ekToDevice[ekHmac]  = deviceKey;
        emit Enroll(deviceId, tier, ekHmac, STATUS_ACTIVE);
    }

    /**
     * @notice Record a classification. Emits ClassifyEvent. If the
     *         transition results in BANNED, also emits Ban and locks the EK.
     */
    function classify(uint256 roundId, string calldata deviceId,
                      uint8 severity, uint8 stage, string calldata reason)
        external onlyServer
    {
        if (severity > SEV_CRITICAL) revert InvalidSeverity(severity);
        bytes32 deviceKey = keccak256(bytes(deviceId));
        uint256 word = devices[deviceKey];
        if (word == 0) revert DeviceUnknown(deviceKey);

        DeviceState memory d = unpack(word);
        if (d.status == STATUS_BANNED) revert DeviceBanned(deviceKey);
        if (lastRoundSet && roundId <= lastRound) {
            revert StaleRound(roundId, lastRound);
        }

        // THE ANTI-FABRICATION RULE. With requireCommit enabled the server
        // cannot classify a device that did not itself commit a gradient hash
        // for this round. A classification fabricated against a client that
        // never participated is refused by the contract, not merely logged.
        if (requireCommit && commitments[deviceKey][roundId] == bytes32(0)) {
            revert MissingCommit(deviceKey, roundId);
        }

        uint8 prevStatus = d.status;
        _applyRule(d, severity);

        d.lastRound = uint32(roundId);
        devices[deviceKey] = pack(d);
        emit ClassifyEvent(roundId, deviceId, severity, stage, reason, d.status);

        if (prevStatus != STATUS_BANNED && d.status == STATUS_BANNED) {
            bytes32 ek = deviceEk[deviceKey];
            bannedEk[ek] = true;
            emit Ban(roundId, deviceId, ek);
        }
    }

    // =========================================================================
    //                          COMMITMENT LAYER
    // =========================================================================

    /**
     * @notice Bind a wallet to a device. Called by the SERVER after it has
     *         verified, off-chain, that the client signed this wallet address
     *         with the attestation key belonging to the enrolled TPM.
     *
     * @dev onlyServer because the server is the party that verified the TPM
     *      proof. A malicious server could bind a wallet it controls -- but
     *      the binding is PUBLIC, so the client detects it immediately by
     *      reading deviceWallet[myKey]. Detectable, not preventable; the same
     *      class of limitation as T26.
     *
     *      Immutable once set, exactly like tier.
     */
    function bindWallet(string calldata deviceId, address wallet)
        external onlyServer
    {
        if (wallet == address(0)) revert WalletNotBound(bytes32(0));
        bytes32 deviceKey = keccak256(bytes(deviceId));
        if (devices[deviceKey] == 0) revert DeviceUnknown(deviceKey);

        address existing = deviceWallet[deviceKey];
        if (existing != address(0)) {
            if (existing == wallet) return;              // idempotent
            revert WalletAlreadyBound(existing);
        }
        if (walletDevice[wallet] != bytes32(0)) {
            revert WalletAlreadyBound(wallet);           // wallet reuse
        }

        deviceWallet[deviceKey] = wallet;
        walletDevice[wallet]    = deviceKey;
        emit WalletBound(deviceId, wallet);
    }

    /**
     * @notice Commit a gradient hash for a round. Called BY THE CLIENT from
     *         its own bound wallet -- this is the only function in the
     *         contract not restricted to the server.
     *
     * @dev The client commits BEFORE sending the gradient over HTTP. The
     *      server then hashes what it received and compares. Neither party can
     *      subsequently claim a different gradient was sent.
     *
     *      A banned device cannot commit: its wallet is bound to a device
     *      whose status is BANNED, and we check that here. This is what makes
     *      the wallet binding load-bearing rather than decorative.
     */
    function commitGradient(uint256 roundId, bytes32 gradHash) external {
        if (gradHash == bytes32(0)) revert EmptyCommit();

        bytes32 deviceKey = walletDevice[msg.sender];
        if (deviceKey == bytes32(0)) revert NotDeviceWallet(msg.sender);

        uint256 word = devices[deviceKey];
        if (word == 0) revert DeviceUnknown(deviceKey);
        DeviceState memory d = unpack(word);
        if (d.status == STATUS_BANNED) revert DeviceBanned(deviceKey);

        if (commitments[deviceKey][roundId] != bytes32(0)) {
            revert DuplicateCommit(deviceKey, roundId);
        }
        commitments[deviceKey][roundId] = gradHash;
        emit GradientCommitted(roundId, deviceKey, msg.sender, gradHash);
    }

    /**
     * @notice Record that a device did not participate in a round. Needed
     *         because with requireCommit on, classify() refuses a device with
     *         no commit -- without this the server would have no way to record
     *         a genuine absence.
     *
     * @dev Touches no reputation state. A server that falsely marks a present
     *      client absent is detectable: the client's GradientCommitted event
     *      for that round is on chain and contradicts the Absent event.
     */
    function markAbsent(uint256 roundId, string calldata deviceId)
        external onlyServer
    {
        bytes32 deviceKey = keccak256(bytes(deviceId));
        if (devices[deviceKey] == 0) revert DeviceUnknown(deviceKey);
        emit Absent(roundId, deviceId);
    }

    /**
     * @notice Record that the gradient the server received did not hash to
     *         what the client committed. Evidence-only; the server decides
     *         locally whether to drop the update.
     */
    function reportCommitMismatch(uint256 roundId, string calldata deviceId,
                                  bytes32 received)
        external onlyServer
    {
        bytes32 deviceKey = keccak256(bytes(deviceId));
        if (devices[deviceKey] == 0) revert DeviceUnknown(deviceKey);
        emit CommitMismatch(roundId, deviceId,
                            commitments[deviceKey][roundId], received);
    }

    /**
     * @notice The EIP-712 digest a client signs to commit a gradient hash.
     *         Exposed so clients and auditors can reproduce it exactly.
     */
    function commitDigest(bytes32 deviceKey, uint256 roundId, bytes32 gradHash)
        public view returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(COMMIT_TYPEHASH, deviceKey, roundId, gradHash));
        return keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    function _commitSigned(uint256 roundId, bytes32 deviceKey,
                           bytes32 gradHash, uint8 v, bytes32 r, bytes32 s)
        internal
    {
        if (gradHash == bytes32(0)) revert EmptyCommit();
        if (uint256(s) > SECP256K1N_HALF || (v != 27 && v != 28)) {
            revert MalleableSignature();
        }

        uint256 word = devices[deviceKey];
        if (word == 0) revert DeviceUnknown(deviceKey);
        DeviceState memory d = unpack(word);
        if (d.status == STATUS_BANNED) revert DeviceBanned(deviceKey);
        if (commitments[deviceKey][roundId] != bytes32(0)) {
            revert DuplicateCommit(deviceKey, roundId);
        }

        address recovered =
            ecrecover(commitDigest(deviceKey, roundId, gradHash), v, r, s);
        if (recovered == address(0)) revert InvalidSignature(deviceKey);

        address bound = deviceWallet[deviceKey];
        if (bound == address(0)) revert WalletNotBound(deviceKey);
        if (recovered != bound) {
            revert SignerNotDeviceWallet(deviceKey, recovered);
        }

        commitments[deviceKey][roundId] = gradHash;
        emit GradientCommitted(roundId, deviceKey, recovered, gradHash);
    }

    /**
     * @notice Submit every client's signed commitment for a round in one
     *         transaction. The SERVER pays; clients pay nothing and need no
     *         wallet funding, no RPC access, and no node connection.
     *
     * @dev Parallel arrays rather than a struct array, and split v/r/s rather
     *      than bytes[], because both choices materially reduce calldata and
     *      decoding cost -- which is the entire point of batching.
     *
     *      Atomic by design: one bad signature reverts the whole batch. A
     *      partial batch would let a server silently drop a client's
     *      commitment and then claim it was absent. All-or-nothing forces the
     *      server to either submit a well-formed round or none of it.
     */
    function commitBatch(
        uint256 roundId,
        bytes32[] calldata deviceKeys,
        bytes32[] calldata gradHashes,
        uint8[]   calldata vs,
        bytes32[] calldata rs,
        bytes32[] calldata ss
    ) external onlyServer {
        uint256 n = deviceKeys.length;
        if (n == 0) revert EmptyBatch();
        if (gradHashes.length != n || vs.length != n
            || rs.length != n || ss.length != n) {
            revert BatchLengthMismatch();
        }
        for (uint256 i = 0; i < n; ) {
            _commitSigned(roundId, deviceKeys[i], gradHashes[i],
                          vs[i], rs[i], ss[i]);
            unchecked { ++i; }
        }
    }

    /**
     * @notice Classify a device while proving, in the same call, that the
     *         client signed the gradient being classified.
     *
     * @dev THE CHEAP PATH. commitBatch stores one commitment per device per
     *      round, and that SSTORE (22,100 gas for a cold zero-to-nonzero
     *      write) dominates everything else -- it is roughly 60% of the
     *      marginal cost per client. But the commitment does not need to be
     *      STORED to be binding: it needs to be PROVEN at the point where it
     *      matters, which is exactly here.
     *
     *      So this function verifies the signature and throws it away. The
     *      signature itself is permanently recorded in the transaction's
     *      calldata and re-emitted in ClassifyEventSigned, so any third party
     *      can still recover it and check it against DOMAIN_SEPARATOR. The
     *      contract simply does not pay to keep a copy it will never read.
     *
     *      Properties versus commitBatch: identical. Non-repudiation holds
     *      (the signature is unforgeable and publicly recoverable),
     *      anti-fabrication holds (no signature means this function cannot be
     *      called at all), ban lockout holds (status is checked below).
     *
     *      What is lost: getCommit() cannot answer "did this device commit?"
     *      from storage. The answer is in the event log instead.
     */
    function classifySigned(
        uint256 roundId, string calldata deviceId, uint8 severity,
        uint8 stage, string calldata reason,
        bytes32 gradHash, uint8 v, bytes32 r, bytes32 s
    ) external onlyServer {
        bytes32 deviceKey = keccak256(bytes(deviceId));
        _requireSignature(deviceKey, roundId, gradHash, v, r, s);
        uint8 newStatus = _classifyCore(deviceKey, deviceId, roundId, severity);
        emit ClassifyEvent(roundId, deviceId, severity, stage, reason,
                           newStatus);
        emit CommitProof(roundId, deviceKey, gradHash, v, r, s);
    }

    /// @dev Signature validation, factored out of classifySigned to keep that
    ///      function within the EVM's 16-slot stack limit.
    function _requireSignature(bytes32 deviceKey, uint256 roundId,
                               bytes32 gradHash, uint8 v, bytes32 r, bytes32 s)
        internal view
    {
        if (gradHash == bytes32(0)) revert EmptyCommit();
        if (uint256(s) > SECP256K1N_HALF || (v != 27 && v != 28)) {
            revert MalleableSignature();
        }
        address bound = deviceWallet[deviceKey];
        if (bound == address(0)) revert WalletNotBound(deviceKey);
        address recovered =
            ecrecover(commitDigest(deviceKey, roundId, gradHash), v, r, s);
        if (recovered == address(0)) revert InvalidSignature(deviceKey);
        if (recovered != bound) {
            revert SignerNotDeviceWallet(deviceKey, recovered);
        }
    }

    /// @dev State mutation shared by classify() and classifySigned(), so the
    ///      two entry points cannot drift apart. Returns the new status.
    function _classifyCore(bytes32 deviceKey, string calldata deviceId,
                           uint256 roundId, uint8 severity)
        internal returns (uint8)
    {
        if (severity > SEV_CRITICAL) revert InvalidSeverity(severity);
        uint256 word = devices[deviceKey];
        if (word == 0) revert DeviceUnknown(deviceKey);
        DeviceState memory d = unpack(word);
        if (d.status == STATUS_BANNED) revert DeviceBanned(deviceKey);
        if (lastRoundSet && roundId <= lastRound) {
            revert StaleRound(roundId, lastRound);
        }

        uint8 prevStatus = d.status;
        _applyRule(d, severity);
        d.lastRound = uint32(roundId);
        devices[deviceKey] = pack(d);

        if (prevStatus != STATUS_BANNED && d.status == STATUS_BANNED) {
            bytes32 ekh = deviceEk[deviceKey];
            bannedEk[ekh] = true;
            emit Ban(roundId, deviceId, ekh);
        }
        return d.status;
    }

    /// @dev The reputation rule, factored out so classify() and
    ///      classifySigned() cannot drift apart.
    function _applyRule(DeviceState memory d, uint8 severity) internal pure {
        if (severity == SEV_CRITICAL) {
            d.cleanRun = 0;
            d.majorRun = 0;
            d.status = STATUS_BANNED;
        } else if (severity == SEV_POSITIVE || severity == SEV_NEUTRAL) {
            d.s = decay(d.s) + THETA_FP;
            d.cleanRun += 1;
            d.majorRun = 0;
            if (d.cleanRun >= FORGIVE_AFTER) {
                d.f = decay(d.f);
            }
            _transition(d);
        } else {
            d.s = decay(d.s);
            d.f += TAU_FP;
            d.cleanRun = 0;
            if (severity == SEV_MAJOR) {
                d.majorRun += 1;
            } else {
                d.majorRun = 0;
            }
            _transition(d);
        }
    }

    /**
     * @notice Record entry into a probation trial. Reverts if the device has
     *         already used its one-shot rehabilitation (caller must use
     *         exhaustProbation instead) or if the device is not currently on
     *         probation.
     */
    function enterProbation(uint256 roundId, string calldata deviceId)
        external onlyServer
    {
        bytes32 deviceKey = keccak256(bytes(deviceId));
        uint256 word = devices[deviceKey];
        if (word == 0) revert DeviceUnknown(deviceKey);
        DeviceState memory d = unpack(word);
        if (d.status != STATUS_PROBATION) revert NotOnProbation(deviceKey);
        if (rehabUsed[deviceKey]) revert NotOnProbation(deviceKey);
        emit ProbationEnter(roundId, deviceId);
    }

    /**
     * @notice A previously-reinstated device that re-offends: emit
     *         RehabExhausted and Ban. One-shot rehabilitation per
     *         trust/probation.py.
     */
    function exhaustProbation(uint256 roundId, string calldata deviceId)
        external onlyServer
    {
        bytes32 deviceKey = keccak256(bytes(deviceId));
        uint256 word = devices[deviceKey];
        if (word == 0) revert DeviceUnknown(deviceKey);
        if (!rehabUsed[deviceKey]) revert NotOnProbation(deviceKey);

        DeviceState memory d = unpack(word);
        d.status = STATUS_BANNED;
        d.cleanRun = 0;
        d.majorRun = 0;
        devices[deviceKey] = pack(d);
        bytes32 ek = deviceEk[deviceKey];
        bannedEk[ek] = true;

        emit RehabExhausted(roundId, deviceId, ek);
        emit Ban(roundId, deviceId, ek);
    }

    /**
     * @notice Record a probation trial outcome. If PERMANENT_BAN, also bans.
     *         If REINSTATED, marks rehabUsed (one-shot).
     */
    function probationDecision(uint256 roundId, string calldata deviceId,
                               uint8 outcome)
        external onlyServer
    {
        if (outcome > OUT_PERMANENT_BAN) revert OutcomeInvalid(outcome);
        bytes32 deviceKey = keccak256(bytes(deviceId));
        uint256 word = devices[deviceKey];
        if (word == 0) revert DeviceUnknown(deviceKey);
        DeviceState memory d = unpack(word);
        if (d.status != STATUS_PROBATION) revert NotOnProbation(deviceKey);

        emit ProbationDecision(roundId, deviceId, outcome);

        if (outcome == OUT_REINSTATED) {
            // Enforce s >= reinstateFloor(f); leaves f untouched.
            uint64 need = reinstateFloor(d.f);
            if (d.s < need) d.s = need;
            d.status = STATUS_ACTIVE;
            d.cleanRun = 0;
            d.majorRun = 0;
            devices[deviceKey] = pack(d);
            rehabUsed[deviceKey] = true;
        } else if (outcome == OUT_PERMANENT_BAN) {
            d.status = STATUS_BANNED;
            d.cleanRun = 0;
            d.majorRun = 0;
            devices[deviceKey] = pack(d);
            bytes32 ek = deviceEk[deviceKey];
            bannedEk[ek] = true;
            emit Ban(roundId, deviceId, ek);
        }
        // OUT_EXTENDED: record only, no state change.
    }

    /**
     * @notice Close a round. localHead is audit/hashchain.py's head hash
     *         AS OF just before this call (anchors the round's evidence).
     */
    function roundSummary(uint256 roundId, bytes32 participantsHash,
                          bool aggregated, bytes32 localHead)
        external onlyServer
    {
        if (roundClosed[roundId]) revert DuplicateRound(roundId);
        if (lastRoundSet && roundId < lastRound) {
            revert StaleRound(roundId, lastRound);
        }

        emit Round(roundId, participantsHash, aggregated, localHead);
        roundClosed[roundId] = true;
        if (!lastRoundSet || roundId > lastRound) {
            lastRound = roundId;
            lastRoundSet = true;
        }
    }

    // =========================================================================
    //                                READS
    // =========================================================================

    function getDevice(string calldata deviceId) external view returns (uint256) {
        return devices[keccak256(bytes(deviceId))];
    }

    function getDeviceState(string calldata deviceId)
        external view returns (DeviceState memory)
    {
        return unpack(devices[keccak256(bytes(deviceId))]);
    }

    function isBannedEk(bytes32 ekHmac) external view returns (bool) {
        return bannedEk[ekHmac];
    }

    function isRehabUsed(string calldata deviceId) external view returns (bool) {
        return rehabUsed[keccak256(bytes(deviceId))];
    }

    function getCommit(string calldata deviceId, uint256 roundId)
        external view returns (bytes32)
    {
        return commitments[keccak256(bytes(deviceId))][roundId];
    }

    function getWallet(string calldata deviceId) external view returns (address) {
        return deviceWallet[keccak256(bytes(deviceId))];
    }
}
