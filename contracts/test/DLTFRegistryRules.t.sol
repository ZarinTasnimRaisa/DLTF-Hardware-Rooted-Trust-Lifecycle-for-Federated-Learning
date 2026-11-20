// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {DLTFRegistry} from "../src/DLTFRegistry.sol";

/// @title DLTFRegistry trust-state rejection rules (N18-N22)
/// @notice Companion to DLTFRegistryCommit.t.sol. That suite covers the
///         COMMITMENT layer (N24-N28). This one covers the TRUST-STATE
///         rejection rules, which are the half the paper's central claim
///         depends on: the ban ledger constrains a dishonest SERVER OPERATOR,
///         not merely a malicious client.
///
///         Every guarantee in that sentence sits at L3 -- "the contract
///         reverts" -- and until a revert is exercised it is asserted rather
///         than demonstrated. The Python parity suite shows two backends
///         AGREE; agreement against a shared specification is not correctness.
///
///           N18  irreversibility of sanction   BanToActive / DeviceBanned
///           N19  tier immutability             TierMutation
///           N19  one chip, one identity        EkAlreadyRegistered
///           N20  rule-bound writes             structural (L4); observable
///                                              consequence tested instead
///           N21  round ordering integrity      DuplicateRound / StaleRound
///           N22  writer authorisation          UnauthorizedWriter
///
///         forge test --match-contract DLTFRegistryRulesTest -vv
///
/// @dev Three contract behaviours differ from the obvious guess. The tests are
///      written to the SOURCE, not to the guess:
///
///      1. Re-registering a banned EK does NOT revert. register() case A emits
///         WhitewashRejected and returns with no state change. This is
///         deliberate and it is why refusal is cheap (the paper's 27,358 gas):
///         a banned device cannot impose cost by hammering the door.
///         Asserting a revert here would be wrong.
///
///      2. Round ordering is GLOBAL, not per device. classify() checks
///         roundId <= lastRound, and lastRound advances only in
///         roundSummary(). Several classifications share a round id, as they
///         must -- a round has many participants. DuplicateRound belongs to
///         roundSummary() via roundClosed[].
///
///      3. classify() on a banned device reverts DeviceBanned. BanToActive is
///         reachable only through register(), and only when the presented EK
///         differs from the banned one, or case A short-circuits first.
contract DLTFRegistryRulesTest is Test {
    DLTFRegistry reg;

    address server = address(this);
    address outsider = address(0xBEEF);

    string constant DEV_A = "alpha";
    string constant DEV_B = "bravo";
    string constant DEV_C = "charlie";

    uint8 constant TIER_HARDWARE = 1;
    uint8 constant TIER_SOFTWARE = 3;

    uint8 constant SEV_POSITIVE = 0;
    uint8 constant SEV_NEUTRAL = 1;
    uint8 constant SEV_MINOR = 2;
    uint8 constant SEV_MAJOR = 3;
    uint8 constant SEV_CRITICAL = 4;

    uint8 constant STATUS_ACTIVE = 0;
    uint8 constant STATUS_BANNED = 2;

    uint64 constant SCALE = 1_000_000;
    uint64 constant THETA_FP = 400_000;
    uint64 constant TAU_FP = 600_000;

    event WhitewashRejected(string deviceId, bytes32 ekHmac);

    function setUp() public {
        reg = new DLTFRegistry(server, bytes32(0), false);
        reg.register(DEV_A, TIER_HARDWARE, _ek(DEV_A));
        reg.register(DEV_B, TIER_SOFTWARE, _ek(DEV_B));
    }

    function _ek(string memory label) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("ek:", label));
    }

    // =====================================================================
    // N18 -- a sanction is irreversible
    // =====================================================================

    /// The most important test here. If favourable evidence can move a banned
    /// device back toward ACTIVE, O2 is false and the ledger is a log.
    function test_BannedDeviceCannotBeClassifiedAgain() public {
        reg.classify(0, DEV_A, SEV_CRITICAL, 3, "sybil");
        assertEq(reg.getDeviceState(DEV_A).status, STATUS_BANNED, "CRITICAL bans");

        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.DeviceBanned.selector,
                                   keccak256(bytes(DEV_A))));
        reg.classify(1, DEV_A, SEV_POSITIVE, 0, "");

        assertEq(reg.getDeviceState(DEV_A).status, STATUS_BANNED);
    }

    /// No length of clean behaviour launders a ban. The ban is a STATUS, not a
    /// score, so M2's gated decay cannot reach it.
    function test_BanSurvivesManyCleanRounds() public {
        reg.classify(0, DEV_A, SEV_CRITICAL, 3, "sybil");
        for (uint256 r = 1; r < 12; r++) {
            vm.expectRevert();
            reg.classify(r, DEV_A, SEV_NEUTRAL, 0, "");
        }
        assertEq(reg.getDeviceState(DEV_A).status, STATUS_BANNED);
    }

    /// A ban locks the EK, the mechanism the anti-whitewash claim rests on.
    function test_BanLocksTheEndorsementKey() public {
        assertFalse(reg.isBannedEk(_ek(DEV_A)), "EK clean before ban");
        reg.classify(0, DEV_A, SEV_CRITICAL, 3, "sybil");
        assertTrue(reg.isBannedEk(_ek(DEV_A)), "ban must lock the EK");
    }

    /// The whitewash attempt itself, at the contract. This does NOT revert by
    /// design; what must hold is that no device state is created.
    function test_BannedEkCannotReRegisterUnderNewLabel() public {
        reg.classify(0, DEV_A, SEV_CRITICAL, 3, "sybil");

        vm.expectEmit(true, true, true, true);
        emit WhitewashRejected(DEV_C, _ek(DEV_A));
        reg.register(DEV_C, TIER_HARDWARE, _ek(DEV_A));

        assertEq(reg.getDevice(DEV_C), 0,
                 "no device state may be created for a banned EK");
    }

    /// BanToActive is reachable only this way: a banned device re-presented
    /// with a DIFFERENT ek hmac, so the banned-EK short circuit does not fire.
    /// This is a server trying to resurrect a device by swapping its key.
    function test_BannedDeviceCannotBeResurrectedWithNewEk() public {
        reg.classify(0, DEV_A, SEV_CRITICAL, 3, "sybil");
        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.BanToActive.selector,
                                   keccak256(bytes(DEV_A))));
        reg.register(DEV_A, TIER_HARDWARE, _ek("some-other-chip"));
    }

    // =====================================================================
    // N19 -- tier immutability, one chip one identity
    // =====================================================================

    /// Tier governs weight cap, rehabilitation eligibility and ban durability.
    /// A server able to raise a tier grants itself influence it never attested
    /// for. The contract checks tier BEFORE ban status, so this is the most
    /// specific error even on a sanctioned device.
    function test_TierCannotBeChanged() public {
        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.TierMutation.selector,
                                   keccak256(bytes(DEV_B)),
                                   TIER_SOFTWARE, TIER_HARDWARE));
        reg.register(DEV_B, TIER_HARDWARE, _ek(DEV_B));
        assertEq(reg.getDeviceState(DEV_B).tier, TIER_SOFTWARE);
    }

    /// Two labels sharing one EK would give a single module two aggregation
    /// slots, exactly the Sybil property hardware binding removes.
    function test_EkCannotBeClaimedByASecondDevice() public {
        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.EkAlreadyRegistered.selector,
                                   _ek(DEV_A)));
        reg.register(DEV_C, TIER_HARDWARE, _ek(DEV_A));
    }

    /// An active device re-presented with a different EK: refused, or a server
    /// could migrate an identity onto uncertified silicon.
    function test_DeviceCannotSwapItsEk() public {
        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.EkAlreadyRegistered.selector,
                                   _ek(DEV_C)));
        reg.register(DEV_A, TIER_HARDWARE, _ek(DEV_C));
    }

    /// Re-registering identically is a no-op, not an error: enrolment must be
    /// idempotent or a retried request would break the federation.
    function test_IdenticalReRegistrationIsIdempotent() public {
        reg.register(DEV_A, TIER_HARDWARE, _ek(DEV_A));
        assertEq(reg.getDeviceState(DEV_A).status, STATUS_ACTIVE);
    }

    // =====================================================================
    // N20 -- rule-bound writes (L4 structural; consequence tested)
    // =====================================================================

    /// N20 is enforced by the ABSENCE of an interface accepting a trust value,
    /// and absence cannot be tested -- hence Class 4 by inspection. What can
    /// be tested is the consequence: the contract RECOMPUTES from a severity.
    /// If s tracks s <- floor(9s/10) + THETA exactly, the contract applies the
    /// rule rather than storing what it was handed.
    function test_ContractRecomputesEvidenceRatherThanStoringIt() public {
        reg.classify(0, DEV_A, SEV_NEUTRAL, 0, "");
        assertEq(uint256(reg.getDeviceState(DEV_A).s), 400_000, "1 NEUTRAL");

        reg.classify(1, DEV_A, SEV_NEUTRAL, 0, "");
        assertEq(uint256(reg.getDeviceState(DEV_A).s), 760_000, "2 NEUTRALs");

        reg.classify(2, DEV_A, SEV_NEUTRAL, 0, "");
        assertEq(uint256(reg.getDeviceState(DEV_A).s), 1_084_000, "3 NEUTRALs");
    }

    /// The goodwill ceiling s_max = THETA/(1-GAMMA) = 4.0 makes the sleeper
    /// unprofitable: no length of good behaviour buys a cushion large enough
    /// to absorb a sanction.
    ///
    /// In the integer mirror the recurrence s <- floor(9s/10) + THETA does NOT
    /// settle on 4_000_000. Its fixed point is 3_999_991, reached at iteration
    /// 129 and stationary thereafter, because the floor takes a little off
    /// every step. That is not a defect: the deficit is 9 units = 9e-6, and
    /// the paper derives eps_max = (1/S)/(1-GAMMA) = 1e-5 as the bound on
    /// exactly this accumulated truncation. So the measured deficit sitting
    /// just inside 10 units is Equation (2)'s derivation confirmed on-chain,
    /// which is a stronger result than a round number would have been.
    ///
    /// Three properties are asserted: the ceiling is never exceeded, the
    /// sequence reaches a true fixed point, and the gap to the ideal ceiling
    /// stays within the derived bound.
    function test_PositiveEvidenceSaturatesAtCeiling() public {
        for (uint256 r = 0; r < 200; r++) {
            reg.classify(r, DEV_A, SEV_NEUTRAL, 0, "");
        }
        uint256 s = uint256(reg.getDeviceState(DEV_A).s);

        assertLe(s, 4 * uint256(SCALE), "s must never exceed the ceiling");

        // stationary: one further clean round must not move it
        reg.classify(200, DEV_A, SEV_NEUTRAL, 0, "");
        assertEq(uint256(reg.getDeviceState(DEV_A).s), s,
                 "s must have reached a fixed point");

        // and the fixed point must sit within the derived truncation bound
        // eps_max = (1/S)/(1-GAMMA) = 1e-5, i.e. 10 units at S = 1e6
        assertLe(4 * uint256(SCALE) - s, 10,
                 "deficit must be within eps_max derived in Eq. (2)");
    }

    /// Severity selects a RULE, not a magnitude. MINOR and MAJOR add identical
    /// negative evidence; only majorRun differs, which is what drives M3. If
    /// these diverge, a sanction becomes offsettable by accumulation and a
    /// core claim in the paper is false.
    function test_MinorAndMajorCarryIdenticalEvidenceWeight() public {
        reg.classify(0, DEV_A, SEV_MINOR, 1, "");
        reg.classify(0, DEV_B, SEV_MAJOR, 2, "");

        DLTFRegistry.DeviceState memory a = reg.getDeviceState(DEV_A);
        DLTFRegistry.DeviceState memory b = reg.getDeviceState(DEV_B);

        assertEq(uint256(a.f), uint256(TAU_FP), "MINOR adds TAU");
        assertEq(uint256(a.f), uint256(b.f), "MINOR and MAJOR weigh the same");
        assertEq(uint256(a.majorRun), 0, "MINOR must not arm M3");
        assertEq(uint256(b.majorRun), 1, "MAJOR must arm M3");
    }

    // =====================================================================
    // N21 -- round ordering integrity
    // =====================================================================

    /// Closing a round twice would let a server anchor two rosters for one
    /// round.
    function test_RoundCannotBeClosedTwice() public {
        reg.roundSummary(0, keccak256("roster"), true, bytes32(0));
        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.DuplicateRound.selector, 0));
        reg.roundSummary(0, keccak256("roster"), true, bytes32(0));
    }

    /// Going backwards would let a server interleave fabricated history
    /// beneath rounds already anchored.
    function test_RoundSummaryCannotGoBackwards() public {
        reg.roundSummary(5, keccak256("roster"), true, bytes32(0));
        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.StaleRound.selector, 3, 5));
        reg.roundSummary(3, keccak256("roster"), true, bytes32(0));
    }

    /// Once a round is closed, no further classification may be attributed to
    /// it or to any earlier round: that record is final.
    function test_ClassifyRejectedForClosedRound() public {
        reg.classify(0, DEV_A, SEV_NEUTRAL, 0, "");
        reg.roundSummary(0, keccak256("roster"), true, bytes32(0));

        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.StaleRound.selector, 0, 0));
        reg.classify(0, DEV_A, SEV_NEUTRAL, 0, "");
    }

    /// Many devices share one round id -- a round has many participants -- so
    /// the ordering rule must not forbid that.
    function test_ManyDevicesMayShareOneRound() public {
        reg.classify(3, DEV_A, SEV_NEUTRAL, 0, "");
        reg.classify(3, DEV_B, SEV_NEUTRAL, 0, "");
        assertEq(uint256(reg.getDeviceState(DEV_A).cleanRun), 1);
        assertEq(uint256(reg.getDeviceState(DEV_B).cleanRun), 1);
    }

    // =====================================================================
    // N22 -- writer authorisation
    // =====================================================================

    function test_OutsiderCannotClassify() public {
        vm.prank(outsider);
        vm.expectRevert(DLTFRegistry.UnauthorizedWriter.selector);
        reg.classify(0, DEV_A, SEV_CRITICAL, 3, "forged");
    }

    function test_OutsiderCannotRegister() public {
        vm.prank(outsider);
        vm.expectRevert(DLTFRegistry.UnauthorizedWriter.selector);
        reg.register(DEV_C, TIER_HARDWARE, _ek(DEV_C));
    }

    function test_OutsiderCannotCloseARound() public {
        vm.prank(outsider);
        vm.expectRevert(DLTFRegistry.UnauthorizedWriter.selector);
        reg.roundSummary(0, keccak256("roster"), true, bytes32(0));
    }

    /// A server must not manufacture history for a device that never enrolled.
    function test_UnknownDeviceCannotBeClassified() public {
        vm.expectRevert(
            abi.encodeWithSelector(DLTFRegistry.DeviceUnknown.selector,
                                   keccak256(bytes(DEV_C))));
        reg.classify(0, DEV_C, SEV_NEUTRAL, 0, "");
    }

    // =====================================================================
    // cross-cutting cost claim
    // =====================================================================

    /// Refusing a whitewash must cost LESS than admitting a device, or
    /// enforcement becomes a denial-of-service surface. The paper reports
    /// 27,358 against 95,344; this is the same claim from a different runner.
    function test_RefusalIsCheaperThanAdmission() public {
        uint256 g0 = gasleft();
        reg.register(DEV_C, TIER_HARDWARE, _ek(DEV_C));
        uint256 admitCost = g0 - gasleft();

        reg.classify(0, DEV_C, SEV_CRITICAL, 3, "sybil");

        g0 = gasleft();
        reg.register("delta", TIER_HARDWARE, _ek(DEV_C)); // silent refusal
        uint256 refuseCost = g0 - gasleft();

        emit log_named_uint("admit gas", admitCost);
        emit log_named_uint("refuse gas", refuseCost);
        assertLt(refuseCost, admitCost, "refusing must be the cheap path");
        assertEq(reg.getDevice("delta"), 0, "refused device must not exist");
    }
}
