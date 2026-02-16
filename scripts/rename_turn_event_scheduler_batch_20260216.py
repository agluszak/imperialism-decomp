#@author codex
#@category Analysis

from ghidra.program.model.symbol import SourceType

fm = currentProgram.getFunctionManager()

RENAMES = [
    (0x004daf00, "DispatchTurnEvent11F8WithNoPayload"),
    (0x004df5c0, "DispatchTurnEvent2103WithNationFromRecord"),
    (0x0050d310, "DispatchTurnEvent3B8AndWaitForCompletionFlag"),
    (0x0050ed4d, "RebuildGlobalMapStateAndMaybeDispatchTurnEvent3C0"),
    (0x0057f3c0, "DispatchTurnEvent2134AndRefreshNationPanels"),
    (0x00584b70, "DispatchUiMouseMoveThenClearTurnEvent"),
    (0x005a4790, "InitializeBattleSetupAndMaybeDispatchTurnEventED8"),
    (0x004fb990, "HandleCommand10AndPostTurnEvent7E0"),
    (0x00544540, "EnsureGameFlowStateAndPostTurnEvent5E5"),
    (0x00544f30, "ResetGameFlowStateAndPostTurnEvent5DC"),
    (0x00545290, "ResetGameFlowStateAndPostTurnEvent5DCAlt"),
    (0x00545320, "ApplyJoinGameSelectionAndPostTurnEvent5E4"),
    (0x00577e40, "ApplyNationSelectionAndMaybePostTurnEvent5E4"),
    (0x005db620, "HandleTurnStateExitAndPostFollowupEventCode"),
    (0x00576230, "HandleSetupDialogCommandTagsAndDispatchEvents"),
    (0x00542520, "ResetGameFlowPromptStateAndPostTurnEvent5E5"),
    (0x0056d190, "HandleTurnFlowStateTickOrPostTurnEvent5DC"),
    (0x00544fc0, "ValidateGameFlowNameAndSelectionContext"),
    (0x00544ff0, "ValidateAndPrepareGameFlowNameForDispatch"),
    (0x005e3c20, "OpenJoinGameRuntimeSelectionAndStartSession"),
    (0x00508910, "ShowCountrySelectionPromptAndReturnNationId"),
]

PLATE_COMMENTS = {
    0x00576230: "Dispatches setup/menu command tags and posts follow-up turn-event codes (load/random/scenario/join/multiplayer paths).",
    0x005db620: "Handles turn-state exit branch by current localization state and posts follow-up event code (5DC/7E0/5EB/or reinit).",
    0x0050ed4d: "Rebuilds global map/runtime state, dispatches turn-event 3C0 on rebuild path, and refreshes dependent systems.",
    0x00577e40: "Applies selected nation/country setup, updates localization/gameflow fields, and conditionally posts event 5E4.",
    0x00544ff0: "Validates/normalizes game-flow name state and marks localization mode for subsequent dispatch.",
}

print("=== rename_turn_event_scheduler_batch_20260216 ===")

renamed = 0
already = 0
missing = 0
failed = 0

for addr_int, new_name in RENAMES:
    addr = toAddr(addr_int)
    fn = fm.getFunctionAt(addr)
    if fn is None:
        fn = fm.getFunctionContaining(addr)
        if fn is not None and fn.getEntryPoint() != addr:
            fn = None

    if fn is None:
        print("MISSING  0x%08X  -> %s" % (addr_int, new_name))
        missing += 1
        continue

    old_name = fn.getName()
    if old_name == new_name:
        print("ALREADY  0x%08X  %s" % (addr_int, old_name))
        already += 1
    else:
        try:
            fn.setName(new_name, SourceType.USER_DEFINED)
            print("RENAMED  0x%08X  %s -> %s" % (addr_int, old_name, new_name))
            renamed += 1
        except Exception as e:
            print("FAILED   0x%08X  %s -> %s  (%s)" % (addr_int, old_name, new_name, str(e)))
            failed += 1

    if addr_int in PLATE_COMMENTS:
        try:
            fn2 = fm.getFunctionAt(addr)
            if fn2 is not None:
                fn2.setComment(PLATE_COMMENTS[addr_int])
                print("COMMENT  0x%08X" % addr_int)
        except Exception as e:
            print("COMMENT_FAIL 0x%08X (%s)" % (addr_int, str(e)))

print("SUMMARY renamed=%d already=%d missing=%d failed=%d" % (renamed, already, missing, failed))
