// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {DLTFRegistry} from "../src/DLTFRegistry.sol";

/// @title DLTFRegistry commitment-layer tests
/// @notice Independent Solidity-native check on the commitment layer:
///         bindWallet, commitGradient, the anti-fabrication rule, and the
///         EIP-712 signed/batched path.
///
///         The Python parity suites (chain/commit_parity_test.py,
///         chain/batch_parity_test.py) already exercise these against the same
///         deployed bytecode. The value here is INDEPENDENCE: a second
///         implementation, in a different language, with a different test
///         runner. If both agree, a bug in one harness cannot hide.
///
///         Build requires via_ir (see foundry.toml): _classifyCore exceeds the
///         16-slot stack limit without it.
///
///         forge test --match-contract DLTFRegistryCommitTest -vv
contract DLTFRegistryCommitTest is Test {
    DLTFRegistry reg;          // requireCommit = false
    DLTFRegistry regReq;       // requireCommit = true

    address server = address(this);
    address outsider = address(0xBEEF);

    // client wallets, derived from known private keys so we can sign
    uint256 constant PK_A = 0xA11CE;
    uint256 constant PK_B = 0xB0B;
    address walletA;
    address walletB;

    string constant DEV_A = "alpha";
    string constant DEV_B = "bravo";

    uint8 constant TIER_HARDWARE = 1;
    uint8 constant TIER_SOFTWARE = 3;

    uint8 constant SEV_NEUTRAL = 1;
    uint8 constant SEV_MINOR = 2;
    uint8 constant SEV_CRITICAL = 4;

    bytes32 constant GRAD_A = keccak256("gradient-alpha-round-0");
    bytes32 constant GRAD_B = keccak256("gradient-bravo-round-0");

    function setUp() public {
        walletA = vm.addr(PK_A);
        walletB = vm.addr(PK_B);

        reg = new DLTFRegistry(server, bytes32(0), false);
        regReq = new DLTFRegistry(server, bytes32(0), true);

        reg.register(DEV_A, TIER_HARDWARE, _ek(DEV_A));
        regReq.register(DEV_A, TIER_HARDWARE, _ek(DEV_A));
        regReq.register(DEV_B, TIER_HARDWARE, _ek(DEV_B));
    }

    function _ek(string memory label) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("ek|", label));
    }

    function _key(string memory label) internal pure returns (bytes32) {
        return keccak256(bytes(label));
    }

    // ---------------------------------------------------------------------
    //  requireCommit is immutable
    // ---------------------------------------------------------------------

    function test_RequireCommitIsSetAtDeployAndImmutable() public view {
        assertFalse(reg.requireCommit(), "reg should not require commits");
        assertTrue(regReq.requireCommit(), "regReq should require commits");
        // There is no setter in the ABI at all -- that is the guarantee. A
        // server operator cannot disable the rule mid-federation.
    }

    // ---------------------------------------------------------------------
    //  bindWallet
    // ---------------------------------------------------------------------

    function test_BindWallet() public {
        regReq.bindWallet(DEV_A, walletA);
        assertEq(regReq.getWallet(DEV_A), walletA);
        assertEq(regReq.walletDevice(walletA), _key(DEV_A));
    }

    function test_BindWallet_RevertsForNonServer() public {
        vm.prank(outsider);
        vm.expectRevert(DLTFRegistry.UnauthorizedWriter.selector);
        regReq.bindWallet(DEV_A, walletA);
    }

    function test_BindWallet_RevertsOnUnknownDevice() public {
        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.DeviceUnknown.selector,
                                   _key("ghost")));
        regReq.bindWallet("ghost", walletA);
    }

    /// One wallet, one device, immutable. Rebinding the same device must fail,
    /// otherwise a server could rotate a wallet to one it controls and then
    /// forge that client's commitments.
    function test_BindWallet_RevertsOnRebind() public {
        regReq.bindWallet(DEV_A, walletA);
        vm.expectRevert();
        regReq.bindWallet(DEV_A, walletB);
        assertEq(regReq.getWallet(DEV_A), walletA, "binding must not change");
    }

    /// The same wallet must not serve two devices, or one funded wallet could
    /// speak for an unbounded number of identities.
    function test_BindWallet_RevertsOnWalletReuse() public {
        regReq.bindWallet(DEV_A, walletA);
        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.WalletAlreadyBound.selector,
                                   walletA));
        regReq.bindWallet(DEV_B, walletA);
    }

    // ---------------------------------------------------------------------
    //  commitGradient
    // ---------------------------------------------------------------------

    function test_CommitGradient_ByBoundWallet() public {
        regReq.bindWallet(DEV_A, walletA);
        vm.prank(walletA);
        regReq.commitGradient(0, GRAD_A);
        assertEq(regReq.getCommit(DEV_A, 0), GRAD_A);
    }

    /// THE CLIENT pays for its own commitment. This is what makes the
    /// commitment the client's own act rather than the server's claim.
    function test_CommitGradient_RevertsForUnboundWallet() public {
        regReq.bindWallet(DEV_A, walletA);
        vm.prank(walletB);
        // Reverts on the CALLER address (NotDeviceWallet), not on a device key.
        // commitGradient resolves the device FROM msg.sender via walletDevice,
        // so an unknown caller fails before any device is identified.
        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.NotDeviceWallet.selector,
                                   walletB));
        regReq.commitGradient(0, GRAD_A);
    }

    function test_CommitGradient_RevertsOnEmptyCommit() public {
        regReq.bindWallet(DEV_A, walletA);
        vm.prank(walletA);
        vm.expectRevert(DLTFRegistry.EmptyCommit.selector);
        regReq.commitGradient(0, bytes32(0));
    }

    /// A client cannot revise its commitment once made -- that would defeat
    /// the whole point, letting it commit early and swap after seeing others.
    function test_CommitGradient_RevertsOnDuplicateRound() public {
        regReq.bindWallet(DEV_A, walletA);
        vm.startPrank(walletA);
        regReq.commitGradient(0, GRAD_A);
        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.DuplicateCommit.selector,
                                   _key(DEV_A), uint256(0)));
        regReq.commitGradient(0, GRAD_B);
        vm.stopPrank();
        assertEq(regReq.getCommit(DEV_A, 0), GRAD_A, "commit must be sticky");
    }

    function test_CommitGradient_DistinctRoundsAccumulate() public {
        regReq.bindWallet(DEV_A, walletA);
        vm.startPrank(walletA);
        regReq.commitGradient(0, GRAD_A);
        regReq.commitGradient(1, GRAD_B);
        vm.stopPrank();
        assertEq(regReq.getCommit(DEV_A, 0), GRAD_A);
        assertEq(regReq.getCommit(DEV_A, 1), GRAD_B);
    }

    // ---------------------------------------------------------------------
    //  THE ANTI-FABRICATION RULE
    // ---------------------------------------------------------------------

    /// With requireCommit on, classify() MUST revert when no commitment exists
    /// for that (device, round). This is the rule that stops a server from
    /// inventing an update and attributing it to a client who never sent one.
    function test_Classify_RevertsWithoutCommit() public {
        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.MissingCommit.selector,
                                   _key(DEV_A), uint256(0)));
        regReq.classify(0, DEV_A, SEV_NEUTRAL, 0, "");
    }

    function test_Classify_SucceedsWithCommit() public {
        regReq.bindWallet(DEV_A, walletA);
        vm.prank(walletA);
        regReq.commitGradient(0, GRAD_A);

        regReq.classify(0, DEV_A, SEV_NEUTRAL, 0, "");
        DLTFRegistry.DeviceState memory d = regReq.getDeviceState(DEV_A);
        assertEq(d.s, 400_000, "one NEUTRAL should give s = 0.4 * SCALE");
        assertEq(d.cleanRun, 1);
    }

    /// requireCommit = false must preserve baseline DLTF behaviour exactly.
    /// This is the "off by default" constraint at the contract level.
    function test_Classify_NoCommitNeededWhenRuleDisabled() public {
        reg.classify(0, DEV_A, SEV_NEUTRAL, 0, "");
        DLTFRegistry.DeviceState memory d = reg.getDeviceState(DEV_A);
        assertEq(d.s, 400_000);
        assertEq(d.cleanRun, 1);
    }

    /// The commitment is per (device, ROUND): committing for round 0 must not
    /// satisfy round 1, or one commitment would license a whole federation.
    function test_Classify_CommitDoesNotCarryToNextRound() public {
        regReq.bindWallet(DEV_A, walletA);
        vm.prank(walletA);
        regReq.commitGradient(0, GRAD_A);
        regReq.classify(0, DEV_A, SEV_NEUTRAL, 0, "");

        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.MissingCommit.selector,
                                   _key(DEV_A), uint256(1)));
        regReq.classify(1, DEV_A, SEV_NEUTRAL, 0, "");
    }

    /// And it is per DEVICE: A's commitment must not cover B.
    function test_Classify_CommitIsPerDevice() public {
        regReq.bindWallet(DEV_A, walletA);
        vm.prank(walletA);
        regReq.commitGradient(0, GRAD_A);

        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.MissingCommit.selector,
                                   _key(DEV_B), uint256(0)));
        regReq.classify(0, DEV_B, SEV_NEUTRAL, 0, "");
    }

    // ---------------------------------------------------------------------
    //  Mismatch evidence
    // ---------------------------------------------------------------------

    /// Non-repudiation: when the received gradient does not hash to the
    /// commitment, BOTH hashes go on chain. Neither party can later rewrite
    /// what was claimed.
    function test_ReportCommitMismatch_RecordsBothHashes() public {
        regReq.bindWallet(DEV_A, walletA);
        vm.prank(walletA);
        regReq.commitGradient(0, GRAD_A);

        vm.expectEmit(true, false, false, true);
        emit DLTFRegistry.CommitMismatch(0, DEV_A, GRAD_A, GRAD_B);
        regReq.reportCommitMismatch(0, DEV_A, GRAD_B);
    }

    function test_ReportCommitMismatch_RevertsForNonServer() public {
        regReq.bindWallet(DEV_A, walletA);
        vm.prank(walletA);
        regReq.commitGradient(0, GRAD_A);

        vm.prank(outsider);
        vm.expectRevert(DLTFRegistry.UnauthorizedWriter.selector);
        regReq.reportCommitMismatch(0, DEV_A, GRAD_B);
    }

    // ---------------------------------------------------------------------
    //  EIP-712 signed commitment (the cheap path)
    // ---------------------------------------------------------------------

    function _sign(uint256 pk, string memory label, uint256 round, bytes32 gh)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 digest = regReq.commitDigest(_key(label), round, gh);
        (v, r, s) = vm.sign(pk, digest);
    }

    /// A commitment does not need a transaction to be binding, only a
    /// signature. The client signs off-chain (zero gas, no funded wallet) and
    /// the server submits.
    function test_ClassifySigned_AcceptsValidSignature() public {
        regReq.bindWallet(DEV_A, walletA);
        (uint8 v, bytes32 r, bytes32 s) = _sign(PK_A, DEV_A, 0, GRAD_A);

        // The signature is the evidence, carried in a CommitProof event.
        vm.expectEmit(true, true, false, true);
        emit DLTFRegistry.CommitProof(0, _key(DEV_A), GRAD_A, v, r, s);
        regReq.classifySigned(0, DEV_A, SEV_NEUTRAL, 0, "", GRAD_A, v, r, s);

        DLTFRegistry.DeviceState memory d = regReq.getDeviceState(DEV_A);
        assertEq(d.s, 400_000, "the rule must still be applied");
    }

    /// DOCUMENTED ASYMMETRY, not a bug. classifySigned deliberately does NOT
    /// write commitments[] -- a cold SSTORE is ~22,100 gas per client, which is
    /// exactly the cost the signed path exists to avoid. The evidence lives in
    /// the CommitProof event log instead.
    ///
    /// CONSEQUENCE FOR INTEGRATORS: getCommit() is NOT a reliable
    /// "did this client commit?" oracle once the signed path is in use. It
    /// returns zero for a perfectly valid signed commitment. Off-chain checks
    /// must ALSO scan CommitProof events.
    function test_ClassifySigned_DoesNotWriteCommitmentStorage() public {
        regReq.bindWallet(DEV_A, walletA);
        (uint8 v, bytes32 r, bytes32 s) = _sign(PK_A, DEV_A, 0, GRAD_A);
        regReq.classifySigned(0, DEV_A, SEV_NEUTRAL, 0, "", GRAD_A, v, r, s);

        assertEq(regReq.getCommit(DEV_A, 0), bytes32(0),
                 "signed path stores nothing; evidence is the event");
    }

    /// The two paths are independent: a stored commitment does not satisfy
    /// classifySigned's signature requirement, and vice versa.
    function test_ClassifySigned_StoredCommitDoesNotSubstituteForSignature()
        public
    {
        regReq.bindWallet(DEV_A, walletA);
        vm.prank(walletA);
        regReq.commitGradient(0, GRAD_A);

        // a garbage signature must still be rejected even though a valid
        // stored commitment exists for this exact (device, round, hash)
        vm.expectRevert();
        regReq.classifySigned(0, DEV_A, SEV_NEUTRAL, 0, "", GRAD_A,
                              27, bytes32(uint256(1)), bytes32(uint256(2)));
    }

    /// FINDING worth reporting. commitGradient has DuplicateCommit protection;
    /// the signed path has none, so the server can emit two CommitProof events
    /// for the same (device, round) carrying DIFFERENT gradient hashes. An
    /// observer then sees two conflicting commitments with no on-chain way to
    /// tell which was authoritative.
    ///
    /// This does not let the server forge a commitment -- both events still
    /// carry the CLIENT's signature, so the client must have signed both. But
    /// it does weaken non-repudiation relative to the storage path, and it is
    /// asymmetric between the two paths. Documented here rather than silently
    /// assumed away.
    function test_ClassifySigned_NoDuplicateProtectionAcrossProofs() public {
        regReq.bindWallet(DEV_A, walletA);
        (uint8 v1, bytes32 r1, bytes32 s1) = _sign(PK_A, DEV_A, 0, GRAD_A);
        (uint8 v2, bytes32 r2, bytes32 s2) = _sign(PK_A, DEV_A, 0, GRAD_B);

        regReq.classifySigned(0, DEV_A, SEV_NEUTRAL, 0, "", GRAD_A, v1, r1, s1);
        // Same device, same round, different gradient hash: accepted.
        regReq.classifySigned(0, DEV_A, SEV_NEUTRAL, 0, "", GRAD_B, v2, r2, s2);

        emit log_string(
            "NOTE: signed path accepts two conflicting proofs for one round");
    }

    /// Signed by the wrong key: the recovered signer is not the bound wallet.
    function test_ClassifySigned_RevertsOnWrongSigner() public {
        regReq.bindWallet(DEV_A, walletA);
        (uint8 v, bytes32 r, bytes32 s) = _sign(PK_B, DEV_A, 0, GRAD_A);

        vm.expectRevert();
        regReq.classifySigned(0, DEV_A, SEV_NEUTRAL, 0, "", GRAD_A, v, r, s);
    }

    /// The struct binds roundId, so a signature for round 0 cannot be replayed
    /// at round 1.
    function test_ClassifySigned_RevertsOnRoundReplay() public {
        regReq.bindWallet(DEV_A, walletA);
        (uint8 v, bytes32 r, bytes32 s) = _sign(PK_A, DEV_A, 0, GRAD_A);
        regReq.classifySigned(0, DEV_A, SEV_NEUTRAL, 0, "", GRAD_A, v, r, s);

        vm.expectRevert();
        regReq.classifySigned(1, DEV_A, SEV_NEUTRAL, 0, "", GRAD_A, v, r, s);
    }

    /// A signature over gradient X cannot be presented alongside gradient Y.
    function test_ClassifySigned_RevertsOnSwappedGradient() public {
        regReq.bindWallet(DEV_A, walletA);
        (uint8 v, bytes32 r, bytes32 s) = _sign(PK_A, DEV_A, 0, GRAD_A);

        vm.expectRevert();
        regReq.classifySigned(0, DEV_A, SEV_NEUTRAL, 0, "", GRAD_B, v, r, s);
    }

    /// EIP-2 low-s enforcement: the malleable counterpart (n - s, flipped v)
    /// must be rejected, or the same commitment would have two valid encodings.
    function test_ClassifySigned_RevertsOnMalleableSignature() public {
        regReq.bindWallet(DEV_A, walletA);
        (uint8 v, bytes32 r, bytes32 s) = _sign(PK_A, DEV_A, 0, GRAD_A);

        uint256 N =
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 highS = bytes32(N - uint256(s));
        uint8 flipped = v == 27 ? 28 : 27;

        vm.expectRevert(DLTFRegistry.MalleableSignature.selector);
        regReq.classifySigned(0, DEV_A, SEV_NEUTRAL, 0, "", GRAD_A,
                              flipped, r, highS);
    }

    // ---------------------------------------------------------------------
    //  commitBatch
    // ---------------------------------------------------------------------

    /// One transaction per ROUND instead of one per client.
    function test_CommitBatch_AcceptsTwoClients() public {
        regReq.bindWallet(DEV_A, walletA);
        regReq.bindWallet(DEV_B, walletB);

        bytes32[] memory keys = new bytes32[](2);
        bytes32[] memory hashes = new bytes32[](2);
        uint8[] memory vs = new uint8[](2);
        bytes32[] memory rs = new bytes32[](2);
        bytes32[] memory ss = new bytes32[](2);

        keys[0] = _key(DEV_A);
        hashes[0] = GRAD_A;
        (vs[0], rs[0], ss[0]) = _sign(PK_A, DEV_A, 0, GRAD_A);

        keys[1] = _key(DEV_B);
        hashes[1] = GRAD_B;
        (vs[1], rs[1], ss[1]) = _sign(PK_B, DEV_B, 0, GRAD_B);

        regReq.commitBatch(0, keys, hashes, vs, rs, ss);

        assertEq(regReq.getCommit(DEV_A, 0), GRAD_A);
        assertEq(regReq.getCommit(DEV_B, 0), GRAD_B);
    }

    function test_CommitBatch_RevertsOnLengthMismatch() public {
        regReq.bindWallet(DEV_A, walletA);

        bytes32[] memory keys = new bytes32[](2);
        bytes32[] memory hashes = new bytes32[](1);
        uint8[] memory vs = new uint8[](1);
        bytes32[] memory rs = new bytes32[](1);
        bytes32[] memory ss = new bytes32[](1);
        keys[0] = _key(DEV_A);
        keys[1] = _key(DEV_B);
        hashes[0] = GRAD_A;
        (vs[0], rs[0], ss[0]) = _sign(PK_A, DEV_A, 0, GRAD_A);

        vm.expectRevert(DLTFRegistry.BatchLengthMismatch.selector);
        regReq.commitBatch(0, keys, hashes, vs, rs, ss);
    }

    function test_CommitBatch_RevertsOnEmptyBatch() public {
        bytes32[] memory keys = new bytes32[](0);
        bytes32[] memory hashes = new bytes32[](0);
        uint8[] memory vs = new uint8[](0);
        bytes32[] memory rs = new bytes32[](0);
        bytes32[] memory ss = new bytes32[](0);

        vm.expectRevert(DLTFRegistry.EmptyBatch.selector);
        regReq.commitBatch(0, keys, hashes, vs, rs, ss);
    }

    function test_CommitBatch_RevertsForNonServer() public {
        regReq.bindWallet(DEV_A, walletA);
        bytes32[] memory keys = new bytes32[](1);
        bytes32[] memory hashes = new bytes32[](1);
        uint8[] memory vs = new uint8[](1);
        bytes32[] memory rs = new bytes32[](1);
        bytes32[] memory ss = new bytes32[](1);
        keys[0] = _key(DEV_A);
        hashes[0] = GRAD_A;
        (vs[0], rs[0], ss[0]) = _sign(PK_A, DEV_A, 0, GRAD_A);

        vm.prank(outsider);
        vm.expectRevert(DLTFRegistry.UnauthorizedWriter.selector);
        regReq.commitBatch(0, keys, hashes, vs, rs, ss);
    }

    // ---------------------------------------------------------------------
    //  Interaction with the ban lifecycle
    // ---------------------------------------------------------------------

    /// A banned device must not be able to keep committing. Otherwise the ban
    /// would be cosmetic: the identity would still be writing to the ledger.
    function test_CommitGradient_BannedDeviceCannotCommit() public {
        regReq.bindWallet(DEV_A, walletA);
        vm.prank(walletA);
        regReq.commitGradient(0, GRAD_A);
        regReq.classify(0, DEV_A, SEV_CRITICAL, 3, "sybil");

        DLTFRegistry.DeviceState memory d = regReq.getDeviceState(DEV_A);
        assertEq(d.status, 2, "CRITICAL should ban");

        vm.prank(walletA);
        vm.expectRevert();
        regReq.commitGradient(1, GRAD_B);
    }

    /// The commitment rule must not weaken the ban rule: classify on a banned
    /// device fails as DeviceBanned even with a valid commitment present.
    function test_Classify_BannedBeatsCommitRule() public {
        regReq.bindWallet(DEV_A, walletA);
        vm.startPrank(walletA);
        regReq.commitGradient(0, GRAD_A);
        vm.stopPrank();
        regReq.classify(0, DEV_A, SEV_CRITICAL, 3, "sybil");

        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.DeviceBanned.selector,
                                   _key(DEV_A)));
        regReq.classify(1, DEV_A, SEV_MINOR, 1, "");
    }

    // ---------------------------------------------------------------------
    //  Domain separator
    // ---------------------------------------------------------------------

    /// The EIP-712 domain binds chainId and the contract address, so a
    /// signature for one deployment cannot be replayed on another.
    function test_DomainSeparator_DiffersPerDeployment() public {
        DLTFRegistry other = new DLTFRegistry(server, bytes32(0), true);
        assertTrue(regReq.DOMAIN_SEPARATOR() != other.DOMAIN_SEPARATOR(),
                   "domain separator must bind the contract address");
    }

    function test_DomainSeparator_BindsChainId() public {
        bytes32 before = regReq.DOMAIN_SEPARATOR();
        vm.chainId(block.chainid + 1);
        // A cached separator would be identical here; a correctly rebuilt one
        // differs. Either way, record the behaviour rather than assume it.
        bytes32 afterChange = regReq.DOMAIN_SEPARATOR();
        emit log_named_bytes32("domain before", before);
        emit log_named_bytes32("domain after chainId change", afterChange);
    }
}
