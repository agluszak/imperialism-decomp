# Entry Decompilation Plan

Date: 2026-02-16
Target: Imperialism.exe startup path (process entrypoint -> game initialization entry)

## Objective
- Identify and document the real game startup chain beginning at the PE entrypoint.
- Distinguish CRT/MFC bootstrap from Imperialism-specific initialization.
- Produce a verified first-pass map of the startup call flow with key addresses.

## Current Status
- In progress.
- Core startup chain is now mapped from PE entrypoint through app init and main loop dispatch.
- First posted startup command path (`WM_COMMAND 100`) is now resolved to concrete handlers.

## Progress Log
1. Confirmed process entrypoint:
   - `entry @ 0x005e98b0` is the PE startup function.
   - It performs CRT initialization (heap/TLS/env/argv/startup-info parsing) and then calls:
     - `FUN_005fa7c2(hModule, 0, cmdlineTail, showCmd)`.

2. Confirmed first bootstrap forwarding:
   - `FUN_005fa7c2 @ 0x005fa7c2` is a thin wrapper calling:
     - `FUN_0060d3fc(...)`.

3. Confirmed MFC-style app dispatcher:
   - `FUN_0060d3fc @ 0x0060d3fc`:
     - Calls `FUN_00624e73(...)` to set app/module startup state.
     - Pulls application object via thread/app state.
     - Executes virtual methods at offsets `+0x8c`, `+0x58`, `+0x5c` or `+0x70`.
   - This is the CRT/MFC handoff into application lifecycle virtuals.

4. Identified likely game-specific app init callback:
   - `FUN_00412dc0 @ 0x00412dc0` is reached through thunk `0x00407e19`.
   - Thunk `0x00407e19` is referenced from data pointer `0x0063e328` (vtable-like slot).
   - `FUN_00412dc0` performs substantial game setup:
     - data/resource initialization
     - registry/settings handling
     - font/resource loading
     - UI/thread setup via Afx APIs
     - returns success/failure (`1` on success path)
   - This is a strong candidate for the real game `InitInstance`-equivalent.

5. Confirmed app singleton constructor and vtable base:
   - `ConstructImperialismApplicationSingleton @ 0x00412ac0` sets:
     - `*this = PTR_LAB_0063e2d0`.
   - This resolved the exact lifecycle slot mapping used by `DispatchMfcAppLifecycle`.

6. Confirmed global static app construction path:
   - `InitializeImperialismAppSingletonGlobal @ 0x00412d40`:
     - calls `ConstructImperialismApplicationSingleton` on `DAT_006a1210`.
     - registers `DestroyImperialismAppSingletonGlobal @ 0x00412d70`.
   - `0x00412d40` is referenced by CRT init table data at `0x00692344` and executed during startup init sequence.

7. Confirmed precise virtual slot resolution in lifecycle dispatcher:
   - vtable base: `PTR_LAB_0063e2d0`
   - `[vtable + 0x8C]` -> `InitializeMfcAppDocumentManager @ 0x00622572`
   - `[vtable + 0x58]` -> thunk `0x00407e19` -> `InitializeImperialismApplicationInstance @ 0x00412dc0`
   - `[vtable + 0x5C]` -> `RunImperialismThreadMainLoop @ 0x006055ae`
   - `[vtable + 0x70]` -> thunk `0x00407e14` -> `ShutdownImperialismApplicationInstance @ 0x00413780`

8. Confirmed message-loop path after successful init:
   - `RunImperialismThreadMainLoop` delegates to:
     - `RunMfcThreadMessageLoopCore @ 0x006063cd`
     - which pumps via `PumpMfcThreadMessage @ 0x0060694f` and idle callbacks.

9. Applied naming/documentation directly in Ghidra:
   - Renamed key startup functions to stable semantic names.
   - Added plate comments for:
     - `entry`
     - `DispatchMfcAppLifecycle`
     - `ConstructImperialismApplicationSingleton`
     - `InitializeImperialismApplicationInstance`
     - `InitializeMfcAppDocumentManager`
     - `RunImperialismThreadMainLoop`
     - `RunMfcThreadMessageLoopCore`
     - `ShutdownImperialismApplicationInstance`
     - `InitializeImperialismAppSingletonGlobal`

10. Synced startup chain into Neo4j:
   - Upserted startup `Function` nodes with current names/addresses.
   - Added ordered `STARTUP_NEXT` edges for entry -> lifecycle -> run/failure branches.
   - Startup claim id: `claim_startup_entry_chain_20260216`.
   - Added claim `claim_startup_entry_chain_20260216` with evidence links to:
     - `imperialism-decomp.md` startup section
     - `entry_decompilation_plan.md` progress records

11. Resolved first posted startup command (`WM_COMMAND 100`) from `InitializeImperialismApplicationInstance`:
   - Confirmed post site in `InitializeImperialismApplicationInstance @ 0x00412dc0`:
     - `PostMessageA(mainWndHwnd, 0x111, 100, 0)`.
   - Confirmed frame/window runtime class and message map anchor:
     - `TMacViewMgr_RuntimeClass @ 0x00648628` (class name string = `TMacViewMgr`).
     - `TMacViewMgr_MessageMapDescriptor @ 0x00648640`.
   - Confirmed exact message-map entry:
     - `TMacViewMgr_OnCommand100_MsgEntry @ 0x006487c8`.
     - Raw entry bytes decode to:
       - `nMessage=0x111`, `nCode=0`, `nID=100`, `nLastID=100`, `nSig=0x0C`, `pfn=0x0040132A`.
   - Resolved handler thunk chain:
     - `thunk_DispatchStartupCommand100ToAppSingleton @ 0x0040132a`
     - `-> DispatchStartupCommand100ToAppSingleton @ 0x00484fd0` (loads `ECX = DAT_006a1348`)
     - `-> thunk_HandleStartupCommand100 @ 0x004019fb`
     - `-> HandleStartupCommand100 @ 0x00413950`.
   - `HandleStartupCommand100` calls:
     - `(**(code **)(*g_pLocalizationTable + 0x4c))()`
     - which resolves via `thunk_AdvanceGlobalTurnStateMachine @ 0x00403b0c`
     - to `AdvanceGlobalTurnStateMachine @ 0x0057da70`.

12. Synced WM_COMMAND startup dispatch into Neo4j:
   - Claim id: `claim_startup_wm_command_100_dispatch_20260216` (status: `confirmed`, confidence `0.96`).
   - Evidence id: `ev_startup_wm_command_100_entry_20260216`.
   - Added `STARTUP_NEXT` edges (context=`wm_command_100_dispatch`) across:
     - `0x00412dc0 -> 0x0040132a -> 0x00484fd0 -> 0x004019fb -> 0x00413950 -> 0x0057da70`.

13. Confirmed command-signature semantics for the `WM_COMMAND 100` message-map entry:
   - `TMacViewMgr_OnCommand100_MsgEntry` uses `nSig=0x0C`.
   - In dispatcher `FUN_00606b1f @ 0x00606b1f`, signature `0x0C` is invoked as `(*pfn)()` (no command-id parameter).
   - Therefore command id `100` is a trigger into `HandleStartupCommand100`, not a direct integer argument passed to the handler body.

14. Resolved initial state-machine seed and early transition sequence:
   - Constructor `FUN_0057b9e0` (object later assigned to `g_pLocalizationTable`) writes:
     - `[this+0x04] = 1` (plus `[+0x08]`, `[+0x0C]`, `[+0x10]` also set to `1`).
   - `HandleStartupCommand100` calls vfunc `+0x4C` -> `AdvanceGlobalTurnStateMachine`.
   - In `AdvanceGlobalTurnStateMachine`, early deterministic state assignments are:
     - case `1` -> sets state to `3`
     - case `3` -> sets state to `2`
     - case `2` -> sets state to `0x10`
   - Branch side-effects in these cases depend on globals/flags (`DAT_006a43c0`, `DAT_006a43f0`, `ctx->field52_0x44`, etc.), but the assignment chain itself is code-confirmed.

15. Synced initial-state claim into Neo4j:
   - Claim id: `claim_startup_state_machine_initial_state_20260216` (status: `confirmed`, confidence `0.91`).
   - Evidence id: `ev_state_machine_ctor_initial_state_20260216`.

16. Identified a second confirmed producer of `WM_COMMAND 100`:
   - `HandleDialogResultAndPostCommand100 @ 0x00413f60` posts:
     - `PostMessageA(mainWndHwnd, 0x111, 100, 0)` on accepted-dialog path.
   - This confirms command-100 dispatch is not only a one-time startup trigger from `InitializeImperialismApplicationInstance`; it is also re-queued later from this dialog-driven path.

17. Synced repost path into Neo4j:
   - Claim id: `claim_wm_command_100_repost_from_dialog_20260216` (status: `confirmed`, confidence `0.90`).
   - Evidence id: `ev_wm_command_100_repost_413f60_20260216`.
   - Added `STARTUP_NEXT` edge (context=`wm_command_100_dispatch`) from:
     - `0x00413f60 -> 0x0040132a`.

18. Confirmed duplicate command-100 map entry at app singleton level:
   - App message-map descriptor resolved from app vtable slot `+0x30`:
     - `ImperialismApp_MessageMapDescriptor @ 0x0063e068`
     - `ImperialismApp_MessageMapEntries @ 0x0063e070`
   - Exact app-level command-100 entry:
     - `ImperialismApp_OnCommand100_MsgEntry @ 0x0063e1f0`
     - bytes decode to:
       - `nMessage=0x111`, `nCode=0`, `nID=100`, `nLastID=100`, `nSig=0x0C`, `pfn=0x00407C48`.
   - `0x00407C48` resolves to `thunk_HandleStartupCommand100`, converging to the same concrete handler (`HandleStartupCommand100 @ 0x00413950`).

19. Synced dual-route command-100 mapping into Neo4j:
   - Claim id: `claim_wm_command_100_dual_message_map_routes_20260216` (status: `confirmed`, confidence `0.93`).
   - Evidence id: `ev_wm_command_100_dual_msgmap_entries_20260216`.

20. Resolved invocation anchor for `HandleDialogResultAndPostCommand100 @ 0x00413f60`:
   - App message-map entry:
     - `ImperialismApp_OnCommand8016_MsgEntry @ 0x0063e0b8`
     - decodes to `WM_COMMAND`, `id=0x8016`, `sig=0x0C`, `pfn=0x00402978`.
   - Stub bytes at `0x00402978`:
     - `E9 E3 15 01 00` (`JMP 0x00413f60`).
   - This gives a concrete path:
     - app `WM_COMMAND 0x8016` -> stub `0x00402978` -> `HandleDialogResultAndPostCommand100`.

21. Synced command-`0x8016` bridge into Neo4j:
   - Claim id: `claim_app_command_8016_routes_to_post_command100_20260216` (status: `confirmed`, confidence `0.94`).
   - Evidence id: `ev_app_cmd_8016_stub_to_413f60_20260216`.

22. Confirmed `TMacViewMgr` as concrete frame runtime class in startup doc-template path:
   - Renamed `FUN_006106bd` -> `ConstructImperialismSingleDocTemplate`.
   - Renamed `FUN_00614790` -> `ConstructMfcSingleDocTemplateBase`.
   - In startup init (`0x00412dc0`), call pattern is:
     - `ConstructImperialismSingleDocTemplate(0x80, &CAmbitDocument_runtime, &TMacViewMgr_runtime, &CIncludeView_runtime)`.
   - This confirms prior `CMainFrame` assumptions are stale for this path; the frame runtime class passed by startup code is `TMacViewMgr`.

23. Synced frame-class correction into Neo4j:
   - Claim id: `claim_doc_template_frameclass_tmacviewmgr_20260216` (status: `confirmed`, confidence `0.95`).
   - Evidence id: `ev_doc_template_ctor_uses_tmacviewmgr_20260216`.

24. Mapped `AdvanceGlobalTurnStateMachine` switch tail for state/command cases `0x64..0x72` (one-to-one, code-confirmed):
   - Shared behavior:
     - each case forces `ctx->field1_0x4 = 4` before dispatching its branch action.
   - Confirmed per-case mapping:
     - `0x64` -> dispatch `DAT_006a21bc` vfunc `+0x4C` with event constant `0x2260`.
     - `0x65` -> dispatch `DAT_006a21bc` vfunc `+0x4C` with event constant `0x0547`.
     - `0x66` -> dispatch `DAT_006a21bc` vfunc `+0x4C` with event constant `0x2103`.
     - `0x67` -> conditional dispatch through `DAT_006a21bc` vfunc `+0x4C` with event constant `0x07DA` or `0x07D9` (branch depends on `DAT_006a43d8 + 0x193` flag).
     - `0x68` -> calls current nation vfunc `+0x1C8`, dispatches event `0x07D8`, then calls `thunk_FUN_004f0590` (`0x0040166d`) to sync `DAT_006a43d0 + 0x790` from `g_pLocalizationTable` vfunc `+0x3C`.
     - `0x69` -> calls current nation vfunc `+0x134`, dispatches event `0x07DE`.
     - `0x6A` -> dispatches event `0x07DB`.
     - `0x6B` -> posts thread/window custom message via `thunk_FUN_00414720` (`0x00408715`) with `wParam=0x1036`.
     - `0x6C` -> dispatches event `0x0F3D`.
     - `0x6D` -> sets `ctx->field47_0x3c |= 0x40`, dispatches event `0x08FC`.
     - `0x6E` -> dispatches event `0x10CC`.
     - `0x6F` -> sets `DAT_00695278=-1`, dispatches event `0x05DE`.
     - `0x70` -> sets `DAT_00695278=-2`, dispatches event `0x05DE`.
     - `0x71` -> posts custom message via `thunk_FUN_00414720` with `wParam=0x104F`.
     - `0x72` -> posts custom message via `thunk_FUN_00414720` with `wParam=0x05E4`.

25. Synced partial `0x64..0x72` case map into Neo4j:
   - Claim id: `claim_state_machine_cases_64_72_partial_map_20260216` (status: `confirmed`, confidence `0.94`).
   - Evidence id: `ev_state_machine_cases_64_72_assembly_context_20260216`.

26. Resolved `DAT_006a21bc` vfunc `+0x4C` target:
   - Renamed `FUN_005d7240` -> `DispatchGlobalTurnEventCode`.
   - Confirmed `DAT_006a21bc` constructor:
     - `FUN_005d5060` -> `ConstructGlobalTurnEventState` (vtable `PTR_LAB_0066f120`).
   - Event-code routing in `DispatchGlobalTurnEventCode` now provides concrete handler mapping for startup tail constants:
     - `0x2260` -> `this` vfunc `+0x64`
     - `0x2103` -> `this` vfunc `+0x9C`
     - `0x7D8` -> `this` vfunc `+0x6C`
     - `0x7D9/0x7DA` -> `this` vfunc `+0x5C`
     - `0x7DB` -> `this` vfunc `+0xA8`
     - `0x7DD` -> `this` vfunc `+0xBC`
     - `0x7DE` -> `this` vfunc `+0x84`
     - `0x8FC` -> `thunk_FUN_005d8750`
     - `0xF3D` -> `this` vfunc `+0x110`
     - `0x5DE` -> `this` vfunc `+0x100`.

27. Resolved custom message `0x2420` consumer path:
   - `TMacViewMgr_OnMessage2420_MsgEntry @ 0x006487f8`:
     - `message=0x2420`, `nSig=0x0A`, `pfn=0x004097C8`.
   - Renamed target:
     - `0x00485920` -> `HandleCustomMessage2420DispatchTurnEvent`.
     - `0x004097c8` -> `thunk_HandleCustomMessage2420DispatchTurnEvent`.
   - Handler behavior:
     - forwards `wParam` event code + current slot/nation (`thunk_FUN_00581260()`) to `DispatchGlobalTurnEventCode`.
   - This closes the async branch for state cases `0x6B/0x71/0x72`:
     - state machine posts `0x2420` with `wParam` (`0x1036`, `0x104F`, `0x05E4`)
     - TMacViewMgr consumes and forwards those as event codes to `DispatchGlobalTurnEventCode`.

28. Synced `DAT_006a21bc` dispatcher target into Neo4j:
   - Claim id: `claim_turn_event_dispatcher_vfunc4c_target_20260216` (status: `confirmed`, confidence `0.95`).
   - Evidence id: `ev_vfunc4c_resolves_to_5d7240_20260216`.

29. Synced message-`0x2420` consumer bridge into Neo4j:
   - Claim id: `claim_message_2420_forwards_to_turn_dispatcher_20260216` (status: `confirmed`, confidence `0.95`).
   - Evidence id: `ev_msg2420_entry_and_forwarder_20260216`.

30. Finalized `vtable +0x8C` startup slot semantics (`DAT_006a6120` path):
   - Renamed `InitializeMfcAppDocumentManager @ 0x00622572` -> `InitializeAppDocTemplateManagerAndFlushPending`.
   - Renamed supporting manager functions:
     - `FUN_00619faa` -> `FlushPendingOrAppendDocTemplate`
     - `FUN_00624693` -> `ConstructDocTemplateManagerList`.
   - This slot now reads as a concrete doc-template manager attach/flush step, not an unknown manager placeholder.

31. Synced startup slot `+0x8C` semantics into Neo4j:
   - Claim id: `claim_startup_slot8c_doc_template_flush_20260216` (status: `confirmed`, confidence `0.95`).
   - Evidence id: `ev_slot8c_doc_template_flush_20260216`.

32. Resolved `DispatchGlobalTurnEventCode` virtual targets (`DAT_0066F120` slots) to concrete handlers and applied semantic renames:
   - `+0x5C` -> `HandleTurnEvent7D9Or7DA_UpdateNationResourceAdvisor @ 0x005d8dd0`
   - `+0x64` -> `HandleTurnEvent2260_RefreshMainHudTitles @ 0x005da180`
   - `+0x6C` -> `HandleTurnEvent7D8_ActivateDiplomacyMapView @ 0x005d8040`
   - `+0x84` -> `HandleTurnEvent7DE_RefreshTradeDiplomacyCityTransportSummary @ 0x005d83b0`
   - `+0x9C` -> `HandleTurnEvent2103_RunNationStatusReportUpdate @ 0x005d8c40`
   - `+0xA8` -> `HandleTurnEvent7DB_SelectCityAndRefreshView @ 0x005d7cb0`
   - `+0x100` -> `HandleTurnEvent5DE_RefreshMainView @ 0x005dbd30`
   - `+0x110` -> `HandleTurnEventF3D_PopulateRecentTurnMessages @ 0x005dc690`
   - direct call target for `0x8FC` -> `HandleTurnEvent8FC_RebuildPageTabsAndTitles @ 0x005d8750`
   - helper for repeated `0x5E4` path -> `QueueDeferredUiEventPacket @ 0x005d4b30`.

33. Closed default-path analysis for async startup-tail events (dispatcher-level only; later callback closure in item 52):
   - In `DispatchGlobalTurnEventCode @ 0x005d7240`, event codes `0x1036`, `0x104F`, and `0x10CC` are not explicitly matched in switch ranges.
   - They flow into default/unhandled path at `0x005d78d6` (bookkeeping + trailing map-order refresh checks only).
   - Added disassembly note at `0x005d78d6` to mark this behavior.

34. Closed `0x05E4` behavior in dispatcher:
   - Repeated-event branch (`sVar6 == current_event`) calls:
     - `thunk_QueueDeferredUiEventPacket @ 0x00405100`
     - `-> QueueDeferredUiEventPacket @ 0x005d4b30`
     - with packet id `0x29A`.
   - Added comment at `0x005d7426` documenting this queue path.

35. Converted remaining event constants into handler-level semantics (confidence mixed: structural mapping confirmed; some gameplay labels inferred from tags/callees):
   - `0x2260` -> `HandleTurnEvent2260_RefreshMainHudTitles` (HUD title/tab refresh path).
   - `0x0547` -> inline dispatcher branch updating cursor/main control context; may write selection slot (`main + 0x90`) when control lookup succeeds.
   - `0x2103` -> `HandleTurnEvent2103_RunNationStatusReportUpdate`.
   - `0x07DA/0x07D9` -> shared `HandleTurnEvent7D9Or7DA_UpdateNationResourceAdvisor`.
   - `0x07D8` -> `HandleTurnEvent7D8_ActivateDiplomacyMapView`.
   - `0x07DB` -> `HandleTurnEvent7DB_SelectCityAndRefreshView`.
   - `0x07DE` -> `HandleTurnEvent7DE_RefreshTradeDiplomacyCityTransportSummary`.
   - `0x08FC` -> `HandleTurnEvent8FC_RebuildPageTabsAndTitles`.
   - `0x10CC` -> dispatcher default path at first-stage routing (later resolved to callback handler in item 52).
   - `0x05DE` -> `HandleTurnEvent5DE_RefreshMainView`.
   - `0x1036/0x104F` -> async custom-message events forwarded from `0x2420` into dispatcher default packet path (later resolved to callback handler in item 52).
   - `0x05E4` -> default on first set; repeated-event queue via `QueueDeferredUiEventPacket(...,0x29A,...)`.

36. Synced event-handler mapping + semantics update into Neo4j:
   - Claim id: `claim_turn_event_handler_address_map_20260216` (status: `confirmed`, confidence `0.96`).
   - Claim id: `claim_turn_event_default_unhandled_codes_20260216` (originally `confirmed`; later superseded in item 53).
   - Claim id: `claim_turn_event_semantic_labels_inferred_20260216` (status: `inferred`, confidence `0.78`).
   - Evidence ids:
     - `ev_turn_event_handler_slot_map_20260216`
     - `ev_dispatch_default_unhandled_codes_20260216`
     - `ev_event_handler_string_tags_and_calls_20260216`.

37. Confirmed `g_pLocalizationTable` vtable `+0x84` call convention and ID transform:
   - Constructor `FUN_0057b9e0` sets `g_pLocalizationTable` vtable to `PTR_LAB_00662a58`; slot `+0x84` resolves to `thunk_LoadUiStringByCodeGroupAndOffset @ 0x00407c1b` -> `LoadUiStringByCodeGroupAndOffset @ 0x00580760`.
   - Call convention is confirmed from assembly call sites (`0x005da2a4..0x005da2ac`, `0x005d8863..0x005d886d`):
     - push `out_string_ptr`, push `index`, push `code_group`, call `[vtable + 0x84]`.
   - Wrapper path computes:
     - `LoadStringA id = code_group * 100 + (index + 1)` via `thunk_LoadUiStringResourceByGroupAndIndex @ 0x004994c0`.
   - Practical mapping note:
     - Win32 `LoadStringA` lookup is effectively 16-bit for STRINGTABLE id.
     - Existing TSV extractor (`strenu-strings.tsv`) uses `id = block * 16 + index` (offset by +16 from classic `(block-1)*16+index`), so direct comparisons must account for this.

38. Resolved concrete user-facing text for startup-tail `0x27xx` codes (code-confirmed callsites + decoded ids):
   - `0x2730, idx=0x1E` at `0x005d8486` -> real id `20191` -> TSV id `20207`:
     - `Give Transport Orders \n(current screen)`.
   - `0x2730, idx=0x02` at `0x005d851e` -> real id `20163` -> TSV id `20179`:
     - `Help`.
   - `0x2735, idx=0x05` at `0x005d85cc` -> real id `20666` -> TSV id `20682`:
     - `Transport`.
   - `0x2735, idx=0x06` at `0x005d861e` -> real id `20667` -> TSV id `20683`:
     - `Ledger`.
   - `0x2741, idx=0x00` at `0x005da2a7` -> real id `21861` -> TSV id `21877`:
     - `Deal Book`.
   - `0x274f, idx=0x04..0x06` at `0x005d8868` -> real ids `23265..23267` -> TSV ids `23281..23283`:
     - `Technologies`, `Cost`, `Benefits`.

39. Tightened `0x0547` event meaning from structural-only to slot-sync semantics:
   - Emission sites confirmed in `AdvanceGlobalTurnStateMachine`:
     - `0x0057e942` and `0x0057e4df` both dispatch event `0x0547` and pass current nation slot (`ctx + 0x2e`) as secondary arg.
   - `DispatchGlobalTurnEventCode` `0x0547` branch (`0x005d7398` region) updates cursor/main control context and conditionally writes selected slot to `(main + 0x90)` after control lookup.
   - Current confidence:
     - this is a selected-slot synchronization event across control contexts; deeper gameplay/domain naming still provisional.

40. Constrained unresolved `0x24D9..0x24E7` path:
   - In `FUN_005da360`, constants `0x24d9..0x24e7` feed UI control vfunc `+0x1C8` with bitmask-like secondary args (`0`, `0x100`, `0x10`, `0x1000`), not direct `g_pLocalizationTable +0x84` calls.
   - `STR#ENU.GOB` stringtable inventory (`wrestool -l`) has 314 type-6 blocks and does not include `name=1613`/`1700` ranges expected by naive mapping from these constants.
   - Existing extracted index likewise has no `strtbl-1613` or `strtbl-1700`.
   - Conclusion: treat `0x24d9..0x24e7` as control-state codes (or indirection keys) pending deeper vfunc `+0x1C8` tracing.

41. Resolved `0x24D9..0x24E7` as picture-resource IDs (not string IDs):
   - Traced control class used by tagged panel entries (`dipl`, `dtra`, `city`, `tran`) to `ConstructPictureScreenResourceEntry`, which sets vtable `PTR_LAB_0065f440`.
   - In `PTR_LAB_0065f440`, vfunc `+0x1C8` resolves to `thunk_SetPictureResourceIdAndRefresh @ 0x00408454` (`JMP 0x0048f570`).
   - `thunk_SetPictureResourceIdAndRefresh` behavior:
     - stores selected resource id (`short`) in object state,
     - attempts cached bitmap load (`LoadBmpResourceByIdCached`),
     - falls back to `BuildIndexedBmpResourceById`,
     - optional refresh path.
   - Therefore `0x24d9..0x24e7` in `HandleTurnEvent7DD_RefreshOrderStatusPanelsAndIcons @ 0x005da360` are bitmap/icon resource IDs used for order-status panel visuals, not localization text keys.
   - Confirmed state-pair structure:
     - set A: `0x24d9/0x24db/0x24dd/0x24df`
     - set B: `0x24e1/0x24e3/0x24e5/0x24e7`
     - selection is driven by `TestTurnFlowStatusFlagMask` per category masks (`0x1`, `0x100`, `0x10`, `0x1000`).

42. Finalized `0x0547` as a diplomacy-map selected-nation synchronization event:
   - `DispatchGlobalTurnEventCode` `0x0547` branch (`0x005d7398`, `0x005d7699`) resolves control tag `main`, verifies type/ownership chain with `FUN_00606fc0(..., PTR_s_TDiplomacyMapView_00654f48)`, then writes event arg to `word [main + 0x90]` (`0x005d7413`, `0x005d770a`).
   - Emission sites in `AdvanceGlobalTurnStateMachine` (`0x0057e4df`, `0x0057e942`) pass `ctx + 0x2e` as secondary arg, matching a nation-slot payload.
   - Downstream consumers treat `+0x90` as nation index into `g_apNationStates`:
     - `FUN_004f5410` read at `0x004f549d`,
     - `FUN_005bb2e0` reads at `0x005bb307` and `0x005bb355`,
     - `FUN_005bf930` read at `0x005bffd5`,
     - `FUN_0048ffb0` read at `0x00490016`.
   - Corroborating write outside `0x0547` path:
     - `HandleTurnEvent7D8_ActivateDiplomacyMapView` writes `word [main + 0x90]` at `0x005d8244` after diplomacy control refresh, confirming shared field semantics.

43. Mapped `0x24D9..0x24E7` IDs to concrete bitmap resources in `pictuniv.gob`:
   - Resource names are present directly as bitmap entries:
     - `9433.BMP`, `9435.BMP`, `9437.BMP`, `9439.BMP`, `9441.BMP`, `9443.BMP`, `9445.BMP`, `9447.BMP`.
   - Exact hex/decimal mapping:
     - `0x24d9=9433`, `0x24db=9435`, `0x24dd=9437`, `0x24df=9439`,
     - `0x24e1=9441`, `0x24e3=9443`, `0x24e5=9445`, `0x24e7=9447`.
   - Tag/mask routing in `HandleTurnEvent7DD_RefreshOrderStatusPanelsAndIcons`:
     - `dipl` (`mask 0x1`) uses `0x24d9` when set, `0x24e1` when clear.
     - `dtra` (`mask 0x100`) uses `0x24db` when set, `0x24e3` when clear.
     - `city` (`mask 0x10`) uses `0x24dd` when set, `0x24e5` when clear.
     - `tran` (`mask 0x1000`) uses `0x24df` when set, `0x24e7` when clear.
   - Practical conclusion:
     - These are paired visual-state icon variants per category (not string IDs); determining which side is semantic "active/inactive" still requires producer-bit trace.

44. Resolved visual-state polarity for `0x24D9..0x24E7` pairs via mask-string crosswalk:
   - `TestTurnFlowStatusFlagMask @ 0x00403012` checks `mask & *(this + 0x3c)`.
   - In `HandleTurnEvent7DD_RefreshOrderStatusPanelsAndIcons`, the same masks that select icon IDs also select status strings (`0x2730` group):
     - `mask 0x100` (`dtra`): index `0x13` when set, `0x17` when clear.
     - `mask 0x1` (`dipl`): index `0x14` when set, `0x18` when clear.
     - `mask 0x10` (`city`): index `0x15` when set, `0x19` when clear.
     - `mask 0x1000` (`tran`): index `0x16` when set, `0x1a` when clear.
   - Decoded text (`strenu-strings.tsv`, ids `20196..20203`):
     - set-path strings: `Give Trade/Diplomacy/Industry/Transport Orders`.
     - clear-path strings: `Give ... Orders (no new orders yet)`.
   - Therefore icon polarity is now confirmed:
     - set bits -> `0x24d9/0x24db/0x24dd/0x24df` = orders available.
     - clear bits -> `0x24e1/0x24e3/0x24e5/0x24e7` = no new orders yet.

45. Characterized the additional `mask 0x40` icon branch in `0x7DD` (still partial):
   - In `HandleTurnEvent7DD_RefreshOrderStatusPanelsAndIcons`, branch at `0x005da544` tests `mask 0x40` and applies icon to tag `0x6d6d6170` (`mmap` control path):
     - set -> `0x0419` (`1049`),
     - clear -> `0x24d7` (`9431`).
   - Constructor/setup path at `0x0043e6bd` assigns default `0x0419` to the same `mmap` control, confirming it as baseline visual.
   - Resource extraction confirms both bitmaps in `pictuniv.gob`:
     - `1049.BMP` (base/default look),
     - `9431.BMP` (alternate variant).
   - Current interpretation:
     - this is a dedicated `mmap` icon state toggle (base vs alternate/attention), but final gameplay label for bit `0x40` still needs producer-side trace.

46. Finalized `mask 0x40` as a city-order capability unlock attention-state flag for the `mmap/info` icon:
   - Producer-side proof in `AdvanceGlobalTurnStateMachine` state `0x11`:
     - reads `prev = word [DAT_006a43d8 + 0x262]` at `0x0057e5d1`,
     - calls `UpdateCityOrderCapabilityUnlockProgress`,
     - compares with current `word [DAT_006a43d8 + 0x262]` at `0x0057e5e3`,
     - if unchanged, sets `ctx->field47_0x3c |= 0x40` at `0x0057e5ef`.
   - Field meaning for `+0x262` is code-confirmed from capability subsystem:
     - `ApplyCityOrderCapabilityUnlockByTechId @ 0x005afba0` writes `word [this + 0x262] = nTechId`,
     - defaults initialized in `InitializeCityOrderCapabilityStateDefaults @ 0x005aeff0`,
     - serialized/deserialized explicitly in `Serialize/DeserializeCityOrderCapabilityState`.
   - UI sink (`HandleTurnEvent7DD_RefreshOrderStatusPanelsAndIcons`) now has resolved polarity:
     - `mask 0x40 set` -> icon `0x0419` (`1049`) on `mmap` tag (normal/no-new-capability state),
     - `mask 0x40 clear` -> icon `0x24d7` (`9431`) on `mmap` tag (new capability attention state).
   - Additional setter:
     - state `0x6D` path sets bit `0x40` and dispatches `0x8FC` (`0x0057ea2e`), consistent with an acknowledge/reset update of this indicator.

47. Resolved concrete producer routes for state code `0x6D` (ack/reset path):
   - Identified turn-state setter vfunc target:
     - `SetGlobalTurnStateCodeIfAllowed @ 0x0057d990` (via g_pLocalizationTable vfunc `+0x48`, thunk `0x00406451`).
     - Commits requested state code to `this->state` (`[this+0x4]`) at `0x0057da02`, rotates shadow state fields, and triggers vfunc `+0x44`.
     - Contains explicit acceptance path including code `0x6D` in the protected-context whitelist (`0x0057d9e5` branch).
   - Producer callsites now anchored:
     - input-dispatch path around `0x004ffe93` queues `0x6D` at `0x004fffa3` through vfunc `+0x48`,
     - control-tag dispatch path compares tag `0x6d6d6170` (`mmap`) and queues `0x6D` at `0x00585028`.
   - This closes the event chain:
     - `mmap` interaction / mapped input route -> state `0x6D`
     - `AdvanceGlobalTurnStateMachine` case `0x6D` -> set status bit `0x40` -> dispatch `0x8FC`
     - `0x7DD` sink uses bit `0x40` to choose `1049` (set) vs `9431` (clear).

48. Advanced naming pass for strongest remaining `main + 0x90` consumers:
   - Renamed:
     - `FUN_005bf930` -> `RefreshSelectedNationOrderCompatibilityInfo`
     - `FUN_005bb2e0` -> `BuildSelectedNationOrderCapabilityRows`
   - Added explicit disassembly annotations at the `+0x90` read sites:
     - `0x005bffd5`,
     - `0x005bb307`,
     - `0x005bb355`.
   - These updates anchor selected-nation-slot usage in two core UI update paths while preserving two remaining high-impact `FUN_*` consumers for a later deeper pass.

49. Completed the remaining strongest `main + 0x90` consumer naming pass:
   - Renamed:
     - `FUN_004f5410` -> `HandleSelectedNationActionCommand`
     - `FUN_0048ffb0` -> `RefreshSelectedNationHeaderStatus`
   - Added confirming read-site annotations:
     - `0x004f549d`,
     - `0x00490016`.
   - At this point, the previously tracked strongest unnamed selected-nation-slot consumers have all received first-pass semantic names:
     - `HandleSelectedNationActionCommand` (`0x004f5410`)
     - `BuildSelectedNationOrderCapabilityRows` (`0x005bb2e0`)
     - `RefreshSelectedNationOrderCompatibilityInfo` (`0x005bf930`)
     - `RefreshSelectedNationHeaderStatus` (`0x0048ffb0`).

50. Started closure pass for defaulted startup-tail event codes (`0x1036`, `0x104F`, `0x10CC`) with new producer-side anchors:
   - `0x1036` now has a concrete non-state-machine producer context:
     - `HandleMainMenuCommandAction @ 0x00575900` includes a `pref` command-tag branch that pushes `0x1036` and routes through the same post helper (`thunk_FUN_00414720`) used by state-machine async posting.
   - `0x104F` remains highly constrained:
     - direct push-site in state machine case `0x71` (`0x0057eacc`) is still the only concrete emitter found so far.
   - `0x10CC` remains constrained to state-machine dispatch path:
     - direct push-site in case `0x6E` (`0x0057ea45`) into `DispatchGlobalTurnEventCode`,
     - no concrete downstream handler beyond current dispatcher-default classification yet.
   - Practical outcome:
     - these codes are now better anchored to producer paths, but gameplay/UI semantic labels are still pending.

51. Closed callback-factory chain behind dispatcher-default startup-tail events:
   - `DispatchGlobalTurnEventCode @ 0x005d7240` default branch packet path was traced through:
     - packet setup helper (`thunk_FUN_0048cf10`) and callback manager dispatch (`DAT_006a1b24` vfunc chain),
     - callback iterator core (`0x00491cc0`) that probes registered UI builders until a handler returns a resource object.
   - Registered callback thunks were enumerated and target entrypoints resolved (including `0x004357b0`).

52. Resolved concrete handlers for previously defaulted startup-tail event codes:
   - In callback function `FUN_004357b0 @ 0x004357b0`, direct comparisons are present for all unresolved codes:
     - `CMP EAX,0x104F` at `0x0043a41b`,
     - `CMP EAX,0x1036` at `0x0043a42c`,
     - `CMP EAX,0x10CC` at `0x0043b067`.
   - Branch bodies build dedicated UI resource trees (base/view + main/pict + control groups), confirming these are concrete callback-handled UI/event flows, not true dispatcher-unhandled dead-ends.
   - Additional branch indicators:
     - `0x1036` path includes text-id setup calls using constants such as `0x1035` and `0x103A`,
     - `0x104F` path includes text-id setup constants such as `0x1032` and `0x11F0`,
     - `0x10CC` path includes explicit `0x10CC` text-id setup and `movi`/`main` picture-tag assembly sequence.

53. Synced callback-handler closure into Neo4j and superseded stale default-only claim:
   - New claim id:
     - `claim_turn_event_1036_104f_10cc_callback_handler_20260216` (status: `confirmed`, confidence `0.91`).
   - Evidence id:
     - `ev_fun_004357b0_handles_1036_104f_10cc_20260216`.
   - Superseded prior claim:
     - `claim_turn_event_default_unhandled_codes_20260216` -> status set to `superseded`.

54. Applied semantic rename for the callback event-dialog handler:
   - Renamed `FUN_004357b0` -> `BuildTurnEventDialogUiByCode` in Ghidra.
   - Updated Neo4j `Function` node `func_004357b0` to the same name.
   - Refreshed callback-handler claim text to reference the new function name while preserving address-level proof anchors.

55. Named the default-path callback-factory internals for readable end-to-end flow:
   - `FUN_0048cfd0` -> `DispatchTurnEventPacketThroughDialogFactory`
   - `FUN_00491d80` -> `InvokeDialogFactoryFromPacket`
   - `FUN_00491cc0` -> `RunRegisteredDialogFactoriesByEventCode`
   - `FUN_00491be0` -> `RegisterDialogFactoryCallback`
   - `FUN_00479480` -> `InitializeTurnEventDialogFactoryRegistry`
   - Resulting startup-tail chain is now explicit in decompilation:
     - dispatcher default -> packet dispatch -> factory invoke -> callback iteration -> `BuildTurnEventDialogUiByCode`.

56. Synced callback-factory chain naming/structure into Neo4j:
   - Claim id:
     - `claim_turn_event_default_callback_chain_20260216` (status: `confirmed`, confidence `0.90`).
   - Evidence id:
     - `ev_turn_event_default_callback_chain_20260216`.

57. Added in-binary documentation for callback-factory chain internals:
   - Applied plate comments in Ghidra to:
     - `InitializeTurnEventDialogFactoryRegistry @ 0x00479480`
     - `DispatchTurnEventPacketThroughDialogFactory @ 0x0048cfd0`
     - `InvokeDialogFactoryFromPacket @ 0x00491d80`
     - `RunRegisteredDialogFactoriesByEventCode @ 0x00491cc0`
     - `RegisterDialogFactoryCallback @ 0x00491be0`
   - This makes the previously opaque default-path callback dispatch readable directly from disassembly/decompiler views.

58. Split out event-specific main-picture constructors used by startup-tail branches:
   - Renamed:
     - `FUN_0043d960` -> `ConstructTurnEventMainPictureEntry_1036`
     - `FUN_0043d9c0` -> `ConstructTurnEventMainPictureEntry_104F`
     - `FUN_0043d840` -> `ConstructTurnEventMainPictureEntry_10CC`
   - Added plate comments on all three constructors.
   - Constructor-level distinction is currently vtable-based and branch-local (selected by event-code branch inside `BuildTurnEventDialogUiByCode`).

59. Synced event-specific main-picture constructor split into Neo4j:
   - Claim id:
     - `claim_turn_event_main_picture_constructor_split_20260216` (status: `confirmed`, confidence `0.86`).
   - Evidence id:
     - `ev_turn_event_main_picture_constructor_split_20260216`.

60. Completed dominant helper/sub-builder naming pass under `BuildTurnEventDialogUiByCode`:
   - Renamed repeated allocation/context/layout helpers:
     - `AllocateUiResourceNode @ 0x0041b1c0` (`thunk @ 0x00402072`)
     - `ApplyUiResourceLayoutFromContext @ 0x0041b3d0` (`thunk @ 0x0040772f`)
     - `BindUiResourceTextAndStyle @ 0x0041b490` (`thunk @ 0x00401370`)
     - `ClearUiResourceContext @ 0x0041b5f0` (`thunk @ 0x00405c40`)
     - `PopUiResourcePoolNode @ 0x0041b610` (`thunk @ 0x004054b1`)
     - `SetUiResourceContextFlagsAndMetrics @ 0x00426fa0` (`thunk @ 0x00401613`)
     - `ApplyUiResourceColorTripletFromContext @ 0x00427010` (`thunk @ 0x00409066`)
     - `SetUiResourceContextTagWord @ 0x004270e0` (`thunk @ 0x00402aa4`)
     - `SetUiResourceContextStringCode @ 0x0041b400` (`thunk @ 0x0040623a`)
     - `ZeroUiResourceContextStyleBytes @ 0x0041b420` (`thunk @ 0x00405cef`)
     - `UpdateUiResourceContextMetricWord27 @ 0x0041b570` (`thunk @ 0x0040540c`).
   - Renamed dominant base constructors used across startup-tail branches:
     - `ConstructUiResourceEntryBase @ 0x0048a8e0` (`thunk @ 0x004064e2`)
     - `InitializeUiResourceEntryFrameAndParent @ 0x0048aa60` (`thunk @ 0x004096b5`)
     - `ConstructUiWindowResourceEntryBase @ 0x0048d500` (`thunk @ 0x00407c43`)
     - `ConstructPictureResourceEntryBase @ 0x0048efc0` (`thunk @ 0x00401122`)
     - `ConstructUiTextResourceEntryBase @ 0x0048f890` (`thunk @ 0x0040541b`)
     - `ConstructUiColorTextResourceEntry @ 0x00430950` (`thunk @ 0x00402a8b`)
     - `ConstructUiStatusListTextEntry @ 0x005b6a00` (`thunk @ 0x0040320b`).
   - Fresh decompilation confirms `BuildTurnEventDialogUiByCode` now renders these paths semantically instead of `thunk_FUN_*` placeholders at the dominant call sites.

61. Added/updated Ghidra plate comments for newly named helper/builder core:
   - `ConstructUiWindowResourceEntryBase @ 0x0048d500`
   - `ConstructPictureResourceEntryBase @ 0x0048efc0`
   - `ConstructUiTextResourceEntryBase @ 0x0048f890`
   - `ConstructUiColorTextResourceEntry @ 0x00430950`
   - `ConstructUiStatusListTextEntry @ 0x005b6a00`
   - `InitializeUiResourceEntryFrameAndParent @ 0x0048aa60`
   - `SetUiResourceContextFlagsAndMetrics @ 0x00426fa0`
   - `ApplyUiResourceColorTripletFromContext @ 0x00427010`
   - `BindUiResourceTextAndStyle @ 0x0041b490`
   - `PopUiResourcePoolNode @ 0x0041b610`
   - `UpdateUiResourceContextMetricWord27 @ 0x0041b570`.

62. Synced helper/sub-builder naming pass into Neo4j:
   - Claim id:
     - `claim_turn_event_ui_builder_helper_renames_20260216` (status: `confirmed`, confidence `0.89`).
   - Evidence id:
     - `ev_turn_event_ui_builder_helper_names_20260216`.
   - Upserted/updated function nodes for 19 renamed helper/builder addresses, including `BuildTurnEventDialogUiByCode @ 0x004357b0`.

63. Resolved remaining high-frequency generic constructors to stable vtable-typed names:
   - `ConstructUiResourceEntryType419D8 @ 0x0043d590`
     - thunk: `thunk_ConstructUiResourceEntryType419D8 @ 0x00401190`
     - allocator wrapper: `CreateUiResourceEntryType419D8 @ 0x005787b0`.
   - `ConstructPictureResourceEntryType426B8 @ 0x0043d8f0`
     - thunk: `thunk_ConstructPictureResourceEntryType426B8 @ 0x00404ec1`
     - allocator wrapper: `CreatePictureResourceEntryType426B8 @ 0x0056bbd0`.
   - `ConstructUiTextResourceEntryType66CE00 @ 0x005b5590`
     - thunk: `thunk_ConstructUiTextResourceEntryType66CE00 @ 0x00401bea`.
   - `ConstructUiTextResourceEntryType42B18 @ 0x0043d990`
     - thunk: `thunk_ConstructUiTextResourceEntryType42B18 @ 0x00403805`.
   - Added matching plate comments for these constructor/wrapper nodes.

64. Verified typed-constructor uplift in dispatcher callback via forced redecompilation:
   - `BuildTurnEventDialogUiByCode @ 0x004357b0` now resolves these callsites by name (e.g., `thunk_ConstructUiTextResourceEntryType42B18`, `thunk_ConstructPictureResourceEntryType426B8`, `thunk_ConstructUiResourceEntryType419D8`) instead of raw `thunk_FUN_*`.

65. Synced typed-constructor resolution into Neo4j:
   - Claim id:
     - `claim_turn_event_type_constructor_resolution_20260216` (status: `confirmed`, confidence `0.83`).
   - Evidence id:
     - `ev_turn_event_type_constructor_resolution_20260216`.
   - Upserted/updated function nodes for 11 related addresses (constructor + thunk + wrapper families + `BuildTurnEventDialogUiByCode`).

66. Resolved remaining dominant `0x00570***` constructor wrappers in startup-tail branch builds:
   - Picture-entry families:
     - `ConstructPictureResourceEntryType5EB60 @ 0x00570bb0` (`thunk @ 0x004038fa`)
     - `ConstructPictureResourceEntryType5E6F8 @ 0x005707f0` (`thunk @ 0x00405628`)
     - `ConstructPictureResourceEntryType606E8 @ 0x00572b30` (`thunk @ 0x00403328`)
     - `ConstructPictureResourceEntryType57080 @ 0x00503c90` (`thunk @ 0x004019f6`).
   - UI-entry families:
     - `ConstructUiResourceEntryType60180 @ 0x00572410` (`thunk @ 0x004038ff`)
     - `ConstructUiResourceEntryType62418 @ 0x005796a0` (`thunk @ 0x0040533a`)
     - `ConstructUiResourceEntryType4A098 @ 0x0048e520` (`thunk @ 0x004087fb`)
     - `ConstructUiResourceEntryType4AD90 @ 0x004903a0` (`thunk @ 0x0040913d`)
     - `ConstructUiResourceEntryType4B0C0 @ 0x00491400` (`thunk @ 0x004042c8`)
     - `ConstructUiWindowResourceEntryType4B340 @ 0x00491fb0` (`thunk @ 0x004054ed`)
     - `ConstructUiWindowResourceEntryType572C0 @ 0x00504bf0` (`thunk @ 0x0040834b`).
   - These replace a broad `thunk_FUN_*` set in the `BuildTurnEventDialogUiByCode` call graph with stable type-family names.

67. Added targeted plate comments for newly resolved `0x00570***` and adjacent base-family constructors:
   - `ConstructPictureResourceEntryType5EB60`, `ConstructPictureResourceEntryType5E6F8`,
     `ConstructUiResourceEntryType60180`, `ConstructPictureResourceEntryType606E8`,
     `ConstructUiResourceEntryType62418`, `ConstructUiResourceEntryType4A098`,
     `ConstructUiResourceEntryType4AD90`, `ConstructUiWindowResourceEntryType572C0`,
     `ConstructPictureResourceEntryType57080`, `ConstructUiWindowResourceEntryType4B340`.

68. Synced `0x00570***` constructor-family mapping into Neo4j:
   - Claim id:
     - `claim_turn_event_00570_constructor_type_families_20260216` (status: `confirmed`, confidence `0.80`).
   - Evidence id:
     - `ev_turn_event_00570_constructor_type_families_20260216`.
   - Upserted/updated function nodes for 23 related addresses (constructors, thunks, and `BuildTurnEventDialogUiByCode` anchor).

69. Synced behavior-level selectable-option and join-game flow into Neo4j:
   - Claim id:
     - `claim_turn_event_selectable_option_join_game_flow_20260216`.
   - Evidence id:
     - `ev_turn_event_selectable_option_join_game_flow_20260216`.
   - Upserted/updated function nodes:
     - `ConstructSelectableTextOptionEntryBase @ 0x005b5590`
     - `ConstructSelectableTextOptionEntry @ 0x0043d990`
     - `CreateSelectableTextOptionEntry @ 0x005793f0`
     - `CreateSelectableTextOptionChildEntry @ 0x005798a0`
     - `SetSelectedTextOptionByTag @ 0x005797c0`
     - `HandleSelectableTextOptionEventDispatch @ 0x00579770`
     - `AddJoinableGameOptionEntry @ 0x0054e8e0`
     - `GetSelectedJoinableGameTag @ 0x0054e970`
     - `ShowJoinGameSelectionDialogAndCaptureChoice @ 0x005e30c0`.

70. Continued semantic uplift in constructor stack used by startup-tail UI dispatch:
   - Cursor-tag constructor family:
     - `ConstructUiCursorTextResourceEntry @ 0x00429330`
     - `thunk_ConstructUiCursorTextResourceEntry @ 0x004049bc`
     - behavior evidence: this type is consistently registered with tag `curs` in map/city controls, diplomacy/trade UI init, and turn-event builders.
   - Numeric entry family:
     - `ConstructUiNumericTextEntryBase @ 0x004903a0`
     - `thunk_ConstructUiNumericTextEntryBase @ 0x0040913d`
     - `ConstructUiNumericTextEntry @ 0x00429500`
     - `thunk_ConstructUiNumericTextEntry @ 0x004061b8`
     - behavior evidence: numeric vtable install path and high-frequency usage in university/control numeric readout entries.
   - Clickable picture icon family:
     - `ConstructUiClickablePictureResourceEntry @ 0x005717c0`
     - `thunk_ConstructUiClickablePictureResourceEntry @ 0x00409980`
     - behavior evidence: reused for `civ*`, `agr*`, and command-icon picture slots.
   - Event-specific root window wrappers:
     - `ConstructTurnEventWindowEntryType3B6 @ 0x00500320`
     - `thunk_ConstructTurnEventWindowEntryType3B6 @ 0x00405335`
     - `ConstructTurnEventWindowEntryType7D1_7D2 @ 0x004ffc10`
     - `thunk_ConstructTurnEventWindowEntryType7D1_7D2 @ 0x00408620`.

71. Added/updated plate comments for new semantic constructors:
   - `ConstructUiCursorTextResourceEntry @ 0x00429330`
   - `ConstructUiNumericTextEntryBase @ 0x004903a0`
   - `ConstructUiNumericTextEntry @ 0x00429500`
   - `ConstructUiClickablePictureResourceEntry @ 0x005717c0`
   - `ConstructTurnEventWindowEntryType3B6 @ 0x00500320`
   - `ConstructTurnEventWindowEntryType7D1_7D2 @ 0x004ffc10`.

72. Verification pass (forced redecompilation):
   - `BuildTurnEventDialogUiByCode @ 0x004357b0` now shows:
     - `thunk_ConstructUiNumericTextEntryBase`
     - `thunk_ConstructUiCursorTextResourceEntry`
     - `thunk_ConstructTurnEventWindowEntryType3B6`
     - `thunk_ConstructTurnEventWindowEntryType7D1_7D2`.
   - `BuildUniversityRecruitmentRows` now shows:
     - `thunk_ConstructUiClickablePictureResourceEntry`
     - `thunk_ConstructUiNumericTextEntryBase`
     - `thunk_ConstructUiNumericTextEntry`.

73. Synced cursor/numeric/icon/event-window uplift into Neo4j:
   - Claim id:
     - `claim_turn_event_cursor_numeric_icon_constructor_uplift_20260216` (status: `confirmed`, confidence `0.86`).
   - Evidence id:
     - `ev_turn_event_cursor_numeric_icon_constructor_uplift_20260216`.
   - Upserted/updated 13 function nodes including:
     - `ConstructUiCursorTextResourceEntry`
     - `ConstructUiNumericTextEntryBase`
     - `ConstructUiNumericTextEntry`
     - `ConstructUiClickablePictureResourceEntry`
     - `ConstructTurnEventWindowEntryType3B6`
     - `ConstructTurnEventWindowEntryType7D1_7D2`
     - and `BuildTurnEventDialogUiByCode` anchor.

74. Closed two remaining high-frequency helper gaps from startup-tail UI builder path:
  - Renamed:
    - `FUN_00479b00` -> `PushUiResourcePoolNode` (`thunk @ 0x00403643`).
    - `FUN_00487400` -> `SetUiColorDescriptorGoldTriplet` (`thunk @ 0x00405fec`).
  - Evidence:
    - `PushUiResourcePoolNode` callsites set `ECX = DAT_006a13e0` and push newly allocated nodes before nested builder context operations.
    - `SetUiColorDescriptorGoldTriplet` writes enable byte `+0x10`, magic tag `0x646c6f67` (`gold`), and triplet dwords `+0x14/+0x18`; used by `ApplyUiResourceColorTripletFromContext`.

75. Mapped concrete producer semantics for `0x7D1/0x7D2` using instruction-level constant sweep:
  - Added a Ghidra constant-reference sweep script and confirmed all instruction sites for `0x3B6`, `0x7D1`, `0x7D2`.
  - Key producer resolved:
    - `FUN_004fe840 @ 0x004fe840` (now renamed, see item 76) selects event code by viewport rectangle:
      - if width `< 641` and height `< 481` -> `0x7D1`
      - else -> `0x7D2`.
  - This establishes `0x7D1/0x7D2` as viewport-class variants of the same turn-event dialog flow, not separate gameplay event families.
  - Additional observation:
    - hidden method region around `0x004ffd70` contains state-routing logic and checks current turn-event state values (`0x7D8/0x7D9/0x7DA/0x7DB/0x7DD/0x7DE/0x8FC`) while servicing this dialog family.

76. Promoted event-window names from numeric-family labels to behavior semantics:
  - Renamed:
    - `FUN_004fe840` -> `InitializeTurnOrderNavigationDialogByViewportSize`.
    - `FUN_004ffc10` -> `ConstructTurnOrderNavigationWindowEntryViewportAdaptive`.
    - `FUN_00500320` -> `ConstructTurnEventWindowEntryStaticBackdrop`.
    - `FUN_004ffc60` -> `DestroyTurnOrderNavigationWindowEntryViewportAdaptive`.
    - `FUN_00500350` -> `DestroyTurnEventWindowEntryStaticBackdrop`.
    - `FUN_00500240` -> `DestroyTurnOrderNavigationWindowAndResetManagerSlot`.
    - thunks:
      - `0x00408620` -> `thunk_ConstructTurnOrderNavigationWindowEntryViewportAdaptive`
      - `0x00405335` -> `thunk_ConstructTurnEventWindowEntryStaticBackdrop`.
  - Applied plate comments documenting:
    - viewport-threshold selection semantics (`0x7D1/0x7D2`),
    - static-backdrop role for `0x3B6`,
    - cleanup/reset behavior of the viewport-adaptive destroy path.
  - Note:
    - At this stage, thunk address `0x004064dd` was not yet materialized as a standalone function (resolved later in item 80).

77. Tightened `0x3B6` interpretation from callback/resource correlation:
  - `BuildTurnEventDialogUiByCode` `0x3B6` branch is a minimal root+picture composition with no branch-local interactive controls/text.
  - Resource pipeline around `BuildIndexedBmpResourceById` and related loaders repeatedly references bitmap id `0x3B6` as a shared/default image source path.
  - Current confidence:
    - `0x3B6` is a static-backdrop turn-event dialog variant (image-centric), while exact gameplay producer origin remains data-driven/not yet directly anchored by immediate-code push sites.

78. Recovered thunk-island function bodies and promoted `0x7D1/0x7D2` from layout-only to turn-order navigation semantics:
  - Created missing function boundaries and named:
    - `HandleTurnOrderNavigationCommand @ 0x004ffd70`
    - `UpdateTurnOrderNavigationWindowLayout @ 0x00500160`.
  - Command-handler behavior (`0x004ffd70`) now decompiled and code-confirmed:
    - command codes `0x31..0x35` route through `g_pLocalizationTable` state-setter (`vfunc +0x48`) using state codes `0x69/0x6A/0x67/0x68/0x6D`,
    - guarded against already-active turn-event states `0x7DE/0x7DB/0x7D9/0x7DA/0x7D8/0x8FC`,
    - integrates SFX trigger (`0x1B58`) and end/confirm handling paths.
  - Layout-hook behavior (`0x00500160`) now decompiled:
    - applies viewport-rect-driven update path specifically when active event code is `0x7D1`, then chains class update callback.
  - Renamed related constructor/cleanup path to behavior-level names:
    - `InitializeTurnOrderNavigationDialogByViewportSize @ 0x004fe840`
    - `ConstructTurnOrderNavigationWindowEntryViewportAdaptive @ 0x004ffc10`
    - `DestroyTurnOrderNavigationWindowEntryViewportAdaptive @ 0x004ffc60`
    - `DestroyTurnOrderNavigationWindowAndResetManagerSlot @ 0x00500240`
    - `thunk_ConstructTurnOrderNavigationWindowEntryViewportAdaptive @ 0x00408620`.

79. Anchored upstream `0x3B6` feed to runtime-dispatch paths (beyond callback/resource-only evidence):
  - Added focused scans:
    - immediate `0x3B6` instruction scan: 6 hits total (`BuildTurnEventDialogUiByCode` branch compare/push + bitmap/resource defaults), no direct dispatcher-literal push sites.
    - immediate `0x2420` scan: single posting site in `PostTurnEventCodeMessage2420`.
    - filtered dispatcher-callsite scan (`DispatchGlobalTurnEventCode` via global-object `vfunc +0x4C`): no `0x3B6` immediate push producers.
  - Renamed and documented runtime bridge functions:
    - `FUN_00414720` -> `PostTurnEventCodeMessage2420` (`thunk @ 0x00408715`).
    - `FUN_00413d20` -> `ShowNationSelectDialogAndRedispatchCurrentTurnEvent`.
    - `FUN_0048542a` -> `HandleDialogSelectionAndDispatchTurnEventCode`.
  - Code-anchored conclusion:
    - `0x3B6` arrives at dispatcher through runtime payload fields (`DAT_006A21BC + 0x4` current-event slot and message `wParam` forwarders), not hardcoded immediate producer calls in static code.
    - ultimate gameplay source remains runtime/data-file or packet/script driven (not yet tied to a single static table emitter).

80. Closed residual turn-order-navigation stub/thunk islands around recovered handlers:
  - Materialized/documented:
    - `thunk_InitializeTurnOrderNavigationDialogByViewportSize @ 0x004064dd` (5-byte jump thunk to `0x004FE840`).
    - `NoOpTurnOrderNavigationVtableSlotA @ 0x00500200` (RET stub).
    - `NoOpTurnOrderNavigationVtableSlotB @ 0x00500220` (RET stub).
    - `thunk_NoOpTurnOrderNavigationVtableSlotA @ 0x0040724d`.
    - `thunk_NoOpTurnOrderNavigationVtableSlotB @ 0x00408832`.
  - Added plate comments to preserve intent in disassembly/decompiler views (thunk-table + vtable no-op wiring) for callgraph readability.
  - Note:
    - `ghidra-mcp` function lookup APIs intermittently miss `0x0040724d`/`0x00408832`, but in-transaction script verification confirms these function entries exist and are named.

81. Continued constructor-family semantic uplift using dominant tag-context evidence:
  - Renamed:
    - `ConstructUiResourceEntryType419D8` -> `ConstructUiPlanetListResourceEntry`
      - `thunk_ConstructUiResourceEntryType419D8` -> `thunk_ConstructUiPlanetListResourceEntry`
      - `CreateUiResourceEntryType419D8` -> `CreateUiPlanetListResourceEntry`.
    - `ConstructPictureResourceEntryType426B8` -> `ConstructUiBaseBackdropPictureEntry`
      - `thunk_ConstructPictureResourceEntryType426B8` -> `thunk_ConstructUiBaseBackdropPictureEntry`
      - `CreatePictureResourceEntryType426B8` -> `CreateUiBaseBackdropPictureEntry`.
    - `ConstructUiResourceEntryType62418` -> `ConstructUiGoldLabelResourceEntry`
      - `thunk_ConstructUiResourceEntryType62418` -> `thunk_ConstructUiGoldLabelResourceEntry`.
    - `ConstructPictureResourceEntryType5E6F8` -> `ConstructUiTabCursorPictureEntry`
      - `thunk_ConstructPictureResourceEntryType5E6F8` -> `thunk_ConstructUiTabCursorPictureEntry`.
  - Evidence anchors from callsite setup tags:
    - `plat`, `base`, `gold`, and `curs`/`tab0..tab8`.
  - Kept conservative type-family names for `Type5EB60/60180/4A098` pending stronger cross-module sink confirmation.

82. Synced new function names and claims into Neo4j:
  - Upserted/updated 19 `Function` nodes (constructor families, runtime dispatch bridges, residual thunk/stub entries).
  - Added claim/evidence pairs:
    - `claim_turn_event_constructor_tag_semantic_uplift_20260216`
      - `ev_constructor_tag_context_callsites_20260216`.
    - `claim_turn_event_3b6_runtime_dispatch_source_20260216`
      - `ev_3b6_immediate_scan_and_runtime_dispatch_20260216`.
    - `claim_turn_order_navigation_residual_stub_materialization_20260216`
      - `ev_turn_order_navigation_stub_materialization_20260216`.

83. Closed the previously-listed constructor semantic gap (`Type5EB60/60180/4A098`) and promoted names to tag-backed behavior semantics:
  - `ConstructPictureResourceEntryType5EB60` -> `ConstructUiBattleTabPictureEntry` (`thunk @ 0x004038fa`).
  - `ConstructUiResourceEntryType4A098` -> `ConstructUiCommandTagResourceEntryBase` (`thunk @ 0x004087fb`).
  - `ConstructUiResourceEntryType60180` -> `ConstructUiCommandTagResourceEntry` (`thunk @ 0x004038ff`).
  - Evidence basis:
    - battle-tab callsites (`batt`/`ttab`) for the `5EB60` family,
    - command-tag callsites (`map`/`load`/`quit`/`join`/`name`/`auto`/`curs`/`plat`) for `4A098/60180`.

84. Materialized additional runtime-selection/join-game vtable islands and applied behavior names/comments:
  - `FUN_005e2cf0` -> `AppendJoinableGameDescriptorEntry`.
  - `FUN_005e2bb0` -> `ResetJoinableGameDescriptorBuffer`.
  - `FUN_005e2c80` -> `InitializeJoinGameSelectionDialogState`.
  - `FUN_005e2b50` -> `NoOpJoinGameSelectionVtableSlotA`.
  - `FUN_005e2b70` -> `NoOpJoinGameSelectionVtableSlotB`.
  - `FUN_004804c0` -> `ApplyCtrlScrollAccelerationToListStep`.
  - `FUN_00480820` -> `ReportDirectPlayAssertionStub`.
  - `FUN_0047fd70` -> `ReturnFalseRuntimeSelectionAuxStatus`.
  - `FUN_00511ed0` -> `DispatchTurnEvent7DDForActiveNation`.

85. Reclassified multiple `0x3B6` literals as non-turn-event false positives and tightened the true ingress frontier:
  - Confirmed `0x3B6` usage in `FUN_004995c0` / `BuildIndexedBmpResourceById` / `FUN_0049ce90` is bitmap-cache default loading (`LoadBmpResourceByIdCached(0x3B6)`), not event dispatch.
  - Confirmed `.data` table hit (`0x0069C968`) is codepage table content consumed by `FUN_005eaee0` (codepage setup path), not turn-event payload.
  - Re-ran `DispatchGlobalTurnEventCode (+0x4C)` callsite analysis:
    - dynamic feed remains constrained to:
      - current-slot redispatch (`ShowNationSelectDialogAndRedispatchCurrentTurnEvent`),
      - list-item data dispatch block (`0x004853cf..0x0048543c`),
      - custom-message `wParam` bridge (`HandleCustomMessage2420DispatchTurnEvent`).
  - `PostTurnEventCodeMessage2420` caller sweep found no static `0x3B6` push producers; variable path (`FUN_00581870`) is currently reached from non-`0x3B6` constant callsites in static flow.

86. Flagged a control-flow boundary issue impacting `0x3B6` producer recovery:
  - Region around `0x004851b0/0x0048542a/0x00485920` is split into micro-functions despite contiguous stack-frame code.
  - This likely obscures callback registration/caller xrefs for the list-item-data dispatch block and is now a target for next-pass function-boundary normalization.

87. Followed the callback-factory default branch to a concrete event-code carrier field:
  - `DispatchTurnEventPacketThroughDialogFactory @ 0x0048CFD0` forwards event code as:
    - `CONCAT22(..., (short)pEventPacket[0x18])`
    - into factory-manager invocation (`DAT_006A1B24 vfunc +0x2C`).
  - `InvokeDialogFactoryFromPacket @ 0x00491D80` and `RunRegisteredDialogFactoriesByEventCode @ 0x00491CC0` propagate that same `nEventCode` into registered callbacks.
  - Practical implication:
    - any runtime `0x3B6` that reaches `BuildTurnEventDialogUiByCode` can be sourced from packet field `pEventPacket[0x18]` (structure offset `0x60`), not only from UI list/message wrappers.

88. Attempted boundary normalization around `ShowCityViewSelectionDialog` split region:
  - Scripted removal/recreation pass on `0x004851b0` and `0x0048542a` temporarily created unified range `0x004851b0..0x004854b5`.
  - Subsequent analysis/decompilation reintroduced split-function metadata, but forced decompilation of `ShowCityViewSelectionDialog` still reconstructs full list-populate+dispatch body (with fixed `0x19A` table excluding `0x3B6`).
  - Kept this as an analysis-quality caveat rather than a closed structural fix.

89. Closed static writer trace for packet event field `pEventPacket[0x18]` (`+0x60`) and tightened `0x3B6` reachability boundary:
  - Confirmed packet-field write site in `FUN_0048CF10`:
    - `MOV word ptr [ESI + 0x60], CX` (`0x0048CF72`).
  - Confirmed caller cardinality:
    - only `DispatchGlobalTurnEventCode` callsite `0x005D75F3` (via thunk `0x00408D46`) writes this field.
  - Argument provenance at that callsite:
    - packet arg3/event-code source is loaded from dispatcher local carrying `param_2` (incoming event code),
    - i.e. packet `+0x60` mirrors `DispatchGlobalTurnEventCode` event-code input for default/callback path.
  - Reconfirmed all dynamic `DAT_006A21BC` vfunc `+0x4C` ingress sites (non-immediate event-code pushes):
    - `ShowNationSelectDialogAndRedispatchCurrentTurnEvent` (`PUSH ESI` from `word [g_pUiRuntimeContext + 4]` replay),
    - `ShowCityViewSelectionDialog` (`PUSH EAX` from `LB_GETITEMDATA`; fixed `0x19A` table values exclude `0x3B6`),
    - `HandleCustomMessage2420DispatchTurnEvent` (`PUSH ECX` from message `wParam`).
  - Revalidated `0x2420` producer space:
    - single post helper site (`PostTurnEventCodeMessage2420`),
    - all static call-arg sites are constants (`0x5DC/0x5DD/0x5E4/0x5E5/0x7E0/0x5EB/0x1036/0x104F/...`), no static `0x3B6`.
  - Practical conclusion:
    - no static first-writer of event code `0x3B6` was found in module code;
    - current static model supports `0x3B6` only as runtime/data-origin payload that is replayed/forwarded into dispatch, then copied into packet `+0x60` on default-path factory dispatch.

90. Closed function-boundary stability follow-up for the city-view dispatch region:
  - Rechecked function metadata after forced redecompilation and xref refresh:
    - `ShowCityViewSelectionDialog` is currently a single function body at `0x004851B0..0x004854B5`.
    - No standalone function exists at `0x0048542A` and no direct xrefs target `0x0048542A`.
  - Verified the dynamic dispatch block remains intact inside the unified function:
    - `LB_GETITEMDATA` (`0x199`) result -> `DAT_006A21BC` vfunc `+0x4C`.
  - Practical outcome:
    - prior split-boundary caveat is resolved for current analysis state; callback/caller reconstruction in this region is now stable.

91. Closed the save/load hypothesis branch for `0x3B6` event seeding via `g_pUiRuntimeContext`:
  - Traced `g_pUiRuntimeContext` virtual save/load slots from `LoadGlobalSystemsFromSave` and `SaveGlobalSystemsToStream`:
    - load path calls `(**(code **)(*g_pUiRuntimeContext + 0x18))(stream)`,
    - save path calls `(**(code **)(*g_pUiRuntimeContext + 0x14))(stream)`.
  - Materialized thunk slots in `PTR_LAB_0066f120` and confirmed targets:
    - `thunk_DeserializeTurnEventDispatchState @ 0x00401F4B` -> `DeserializeTurnEventDispatchState @ 0x005D5200`,
    - `thunk_SerializeTurnEventDispatchState @ 0x0040488B` -> `SerializeTurnEventDispatchState @ 0x005D5250`.
  - Code-confirmed deserializer behavior in `DeserializeTurnEventDispatchState`:
    - after base stream read, it explicitly writes `word [this + 0x4] = 0` and clears transient fields.
  - Practical conclusion:
    - persisted save data does not directly preserve/restore a non-zero current turn-event code into `g_pUiRuntimeContext + 0x4`; this path does not explain runtime `0x3B6` ingress.

92. Continued rename-first uplift of unresolved `g_pUiRuntimeContext` helper/vtable wrappers:
  - Renamed and documented:
    - `DispatchTurnEvent3B8AndWaitForCompletion @ 0x005D7C40` (`thunk @ 0x00408869`),
    - `DispatchTurnEvent7D8AndUpdateMainViewSelection @ 0x005D7090` (`thunk @ 0x004094BC`),
    - `DispatchTurnEvent7D8IfTurnFlowIdle @ 0x005D7100` (`thunk @ 0x004079A0`),
    - `ComputeTurnEventDialogPlacementByCode @ 0x005D69B0` (`thunk @ 0x0040666D`),
    - `RefreshMainViewNationIndicatorForCurrentTurnEvent @ 0x005D6B70` (`thunk @ 0x004061DB`).
  - Reclassified and renamed remaining strongest `0x3B6` constant users as resource defaults (not dispatch producers):
    - `ResolveBmpResourceHandleWithDefault3B6 @ 0x004995C0`,
    - `InitializeDefaultBackdropWindowFromBmp3B6 @ 0x0049CE90`.
  - Practical outcome:
    - current `0x3B6` ingress frontier remains runtime-forwarded event payload, while static `0x3B6` literals continue to resolve to dialog branch compare and fallback bitmap loading.

93. Resolved write-set and internal re-dispatch constants for `g_pUiRuntimeContext` event-slot flow:
  - Ran resolved-vtable writer scan over `PTR_LAB_0066f120` and confirmed only these `+0x4` writes in relevant methods:
    - `DeserializeTurnEventDispatchState`: `word [this + 0x4] = 0` (post-load reset),
    - `DispatchGlobalTurnEventCode`: assigns incoming dispatch event code to `word [this + 0x4]`.
  - Additional `+0x4` write observed in `HandleTurnEvent7DB_SelectCityAndRefreshView` was verified as a write to `g_pStrategicMapViewSystem + 4`, not `g_pUiRuntimeContext + 4`.
  - Internal `g_pUiRuntimeContext` methods that call dispatcher `+0x4C` use fixed constants:
    - `DispatchTurnEvent7D8AndUpdateMainViewSelection` -> `0x7D8`,
    - `DispatchTurnEvent7D8IfTurnFlowIdle` -> `0x7D8`,
    - `DispatchTurnEvent3B8AndWaitForCompletion` -> `0x3B8`.
  - Practical conclusion:
    - no resolved in-class helper method dispatches `0x3B6`; this further supports that `0x3B6` ingress is external/data-driven rather than emitted by a static in-class constant route.

94. Materialized previously unmapped `.text` islands containing raw `0x3B6` bytes and reclassified them:
  - Created and renamed:
    - `AssertAmbitSubsystemReadyOrFailWithBmp3B6 @ 0x00414640`,
    - `InitializeGlobalBackdropWindowWithDefaultBmp3B6 @ 0x0049CCA0`.
  - Decompilation confirms both are fallback/default-bitmap paths:
    - assertion/error path uses `(s_D__Ambit_Ambit_cpp_00694290, 0x3B6)`,
    - global backdrop/window init path loads `LoadBmpResourceByIdCached(0x3B6)` into `DAT_006A2050` object lifecycle.
  - Practical conclusion:
    - these newly materialized `0x3B6` literals are resource/assertion defaults, not turn-event dispatch producers.

95. Materialized additional `ReinitializeGameFlowAndPostTurnEventCode` feeder wrappers and tightened argument provenance:
  - Renamed clear wrapper/callback routes:
    - `HandleDoneCommandAndReinitializeGameFlow5E0 @ 0x0057B620` (`thunk @ 0x004041BF`) -> posts `0x5E0`,
    - `ReinitializeGameFlowWithoutPostingTurnEvent @ 0x0049DDB0` (`thunk @ 0x004052DB`) -> posts `0`,
    - `ReinitializeGameFlowAndPostTurnEvent5DD @ 0x005974EB` -> posts `0x5DD`,
    - `HandleCrossUSmallViewsCommandTagDispatch @ 0x00584F27` includes `ResT` branch -> posts `0`.
  - Re-ran call-arg sweep for `thunk_ReinitializeGameFlowAndPostTurnEventCode (0x00403553)` after materialization:
    - observed arguments remain constrained to `0`, `0x5E0`, `0x5DD` (plus already-known constant routes),
    - no `0x3B6` producer route appears in this feeder family.
  - Practical outcome:
    - the `0x2420` repost/reinit path remains a constant-code scheduler path in static analysis and does not surface a static `0x3B6` source.

96. Broadened `g_pUiRuntimeContext` dispatch scan to function-level scope and eliminated newly surfaced false positives:
  - Ran a wide pass over all functions that reference `0x006A21BC`, then inspected every internal `CALL [* + 0x4C]` site.
  - New candidates (e.g., `0x004B6D7C`, `0x004DB095`, `0x004E1DFF`, `0x0051C80C`, `0x00547016`, `0x0054841C`) were all validated as dispatches on non-`g_pUiRuntimeContext` objects (nation/map/manager/control instances).
  - Confirmed true `g_pUiRuntimeContext` dispatcher callsites remain:
    - known dynamic routes (`ShowNationSelectDialogAndRedispatchCurrentTurnEvent`, `ShowCityViewSelectionDialog`, `HandleCustomMessage2420DispatchTurnEvent`),
    - and newly named fixed-constant in-class wrappers (`0x7D8`/`0x3B8` paths).
  - Practical conclusion:
    - no additional static `g_pUiRuntimeContext` event producer route to `0x3B6` was found after widening the search surface.

97. Materialized and renamed a missing `Cross_UArmyViews` command-dispatch island (previously no-function):
  - Materialized:
    - `HandleCrossUArmyViewsCommandTagDispatch @ 0x004A9990`,
    - `thunk_HandleCrossUArmyViewsCommandTagDispatch @ 0x00409903`,
    - `HandleCrossUArmyViewsNameCommand @ 0x004A9CA0`,
    - `thunk_HandleCrossUArmyViewsNameCommand @ 0x00403986`.
  - Confirmed branch tags in dispatcher:
    - `'chec'` (`0x63686563`), `'upgr'` (`0x75706772`), `'name'` (`0x6E616D65`).
  - Clarified `g_pUiRuntimeContext` offset semantics at this site:
    - call at `+0x48` resolves to `RefreshMainViewNationIndicatorForCurrentTurnEvent` (vtable `PTR_LAB_0066F120 + 0x48`),
    - this is a current-event/UI refresh hook using `this+0x4`, not a `DispatchGlobalTurnEventCode (+0x4C)` producer.
  - Practical conclusion:
    - this recovered island improves callgraph readability but does not introduce a new static `0x3B6` dispatch source.

98. Materialized additional scheduler/repost helper islands and applied behavior-level rename uplift:
  - Renamed:
    - `ResetLocalUiStateAndPostTurnEvent5E5 @ 0x00545660` (`thunk @ 0x0040346D`),
    - `PostTurnEvent5DCOrResetLocalUiState @ 0x005781F0` (`thunk @ 0x00405D8A`),
    - `HandleCommand10AndPostTurnEvent5DC @ 0x00575770` (`thunk @ 0x004063CF`).
  - Code-confirmed behavior:
    - `0x00545660` clears local state, calls reset helper (`0x0054C6E0`), then posts `0x5E5`,
    - `0x005781F0` gates between posting `0x5DC` and calling the `0x5E5` reset helper path,
    - `0x00575770` posts `0x5DC` on command id `10` and runs follow-up UI sync helpers.
  - Practical conclusion:
    - newly recovered repost helpers remain fixed-code scheduler routes (`0x5DC/0x5E5`), with no static `0x3B6` emission.

99. Re-validated `g_pUiRuntimeContext +0x4C` producer space after latest materialization with stricter scans:
  - Ran strict and proximity scans for `CALL [* + 0x4C]` plus nearby `0x3B6` literals.
  - Results:
    - no `PUSH 0x3B6` near any `+0x4C` callsite (`TOTAL=0`),
    - no `+0x4C` callsite with nearby `0x3B6` immediate (`TOTAL_MATCHES=0`).
  - Confirmed `+0x4C` sites remain constants plus already-known dynamic payload routes:
    - dynamic: `ShowNationSelectDialogAndRedispatchCurrentTurnEvent`, `ShowCityViewSelectionDialog`, `HandleCustomMessage2420DispatchTurnEvent`,
    - fixed constants: startup/state-machine/repost helpers (`0x11F8`, `0x2103`, `0x3B8`, `0x3C0`, `0x7D8`, `0x7DD`, `0x7DE`, `0x7DB`, `0x8FC`, `0x10CC`, `0x5DE`, `0x5E4`, `0xED8`, etc.).
  - Practical conclusion:
    - no newly materialized static `+0x4C` route emits `0x3B6`; ingress frontier remains runtime/data-driven.

100. Materialized and renamed scenario-selection helper cluster around previously unmapped `0x0057A3**` region:
  - Renamed:
    - `PostTurnEvent5DCOrResetScenarioSelectionState @ 0x0057A2D0` (`thunk @ 0x004039EF`),
    - `HandleScenarioSelectionKeyInput @ 0x0057A310` (`thunk @ 0x00403B75`),
    - `ApplyScenarioSelectionAndPostTurnEvent5E4 @ 0x0057A350` (`thunk @ 0x00407446`).
  - Code-confirmed behavior:
    - `0x0057A2D0` mirrors the `0x5DC` vs reset+`0x5E5` gate pattern based on localization flow flag,
    - `0x0057A310` maps key codes (`3`, `0x0D`, `0x1B`) to virtual accept/cancel actions,
    - `0x0057A350` applies scenario index-dependent state, writes `scn0 + index` marker, and posts `0x5E4` on active flow branch.
  - Practical conclusion:
    - this recovered cluster expands scheduler/selection naming coverage and still does not expose static `0x3B6` dispatch production.

101. Low-hanging rename sweep in `PTR_LAB_0066F120` (vtable thunk family) completed:
  - Materialized unresolved thunk entries and applied high-confidence behavior names:
    - `GetTurnViewManagerClassNamePointer @ 0x005D5040` (`thunk @ 0x00402E7D`),
    - `SetTurnEventStateBaseVtable @ 0x005D50E0`,
    - `DestroyTurnEventState @ 0x005D50B0` (`thunk @ 0x00403053`),
    - `LoadTurnEventCursorByResourceIdOffset1000 @ 0x005D5140`,
    - `LoadTurnEventCursorTable @ 0x005D5100` (`thunk @ 0x004067E9`),
    - `ReleaseTurnEventDialogIfPresent @ 0x005D51E0` (`thunk @ 0x004081A7`),
    - `MapTurnEventCodeToPaletteIndex @ 0x005D5270`,
    - `ApplyTurnEventPaletteColorByEventCode @ 0x005D5750` (`thunk @ 0x00404DF4`),
    - `UpdatePaletteIndexFromTurnEventCode @ 0x005D5780` (`thunk @ 0x0040952F`),
    - `ClassifyTurnStateForOverlayMode @ 0x005D5960` (`thunk @ 0x004068F2`),
    - `BuildAndShowTurnOverlayByMode @ 0x005D6480` (`thunk @ 0x00403E81`),
    - `GetPendingTurnOverlayCode @ 0x005D6C10` (`thunk @ 0x00406AD2`),
    - `RefreshStrategicMapStatusIconsForActiveNation @ 0x005D6C30` (`thunk @ 0x00401064`).
  - Added plate comments for all non-trivial renamed targets above.
  - Practical conclusion:
    - this was a high-yield, low-risk naming pass that improves callgraph readability around turn-event overlay/cursor/palette paths, while maintaining the prior `0x3B6` conclusion (no new static `+0x4C` producer).

102. Continued low-hanging cleanup in same TurnEventState family (small single-purpose helpers):
  - Renamed:
    - `AddPendingTurnOverlayCode @ 0x005D6BF0` (`thunk @ 0x004057CC`),
    - `SetCursorRangeAndRefreshMainPanel @ 0x005D7FC0` (`thunk @ 0x00401EF6`).
  - Code-confirmed behavior:
    - `0x005D6BF0` is a direct `this+0xEC += delta` helper,
    - `0x005D7FC0` configures cursor resource/range (`0x2B6C..0x2B67`) and refreshes main-panel path.
  - Practical conclusion:
    - additional low-risk naming uplift completed without changing the `0x3B6` ingress frontier.

103. Low-hanging forwarding-wrapper uplift (`main` widget dispatch helper):
  - Renamed:
    - `InvokeMainWidgetMethod1CCWithArgs @ 0x005D71B0` (`thunk @ 0x00408E27`).
  - Code-confirmed behavior:
    - resolves `main` widget from view manager resource tree (`DAT_006A2158 + 4 -> vfunc +0x94`),
    - forwards caller argument pack into widget virtual slot `+0x1CC`.
  - Practical conclusion:
    - improved readability for one more vtable slot with no impact on `0x3B6` source conclusions.

104. Additional low-hanging tiny-body/thunk cleanup completed:
  - Renamed:
    - `NoOpTurnEventStateVtableSlot0C @ 0x00412BF0` (`thunk @ 0x004010A0`),
    - `NoOpTurnEventStateVtableSlot10 @ 0x00412C10` (`thunk @ 0x00408625`),
    - `InvokeObjectVtableMethod24 @ 0x004798D0` (`thunk @ 0x00408684`),
    - `InvokeStrategicMapViewMethod6C @ 0x005DC160` (`thunk @ 0x00405BB4`),
    - `InvokeStrategicMapViewMethod74 @ 0x005DC1A0` (`thunk @ 0x00406F23`).
  - Code-confirmed behavior:
    - first two are pure no-op returns,
    - `0x004798D0` is a direct one-call virtual-forwarder (`obj + 0x24`),
    - `0x005DC160`/`0x005DC1A0` are one-call forwarders into strategic-map system vtable slots (`+0x6C`/`+0x74`).
  - Practical conclusion:
    - this pass closed another set of obvious wrappers with minimal ambiguity and improved vtable readability.

105. Closed low-hanging no-function vtable islands plus strategic-map forwarding slots:
  - Materialized and renamed:
    - no-op slot handlers:
      - `NoOpTurnEventStateVtableSlot8C @ 0x005D6E30` (`thunk @ 0x00401CDF`),
      - `NoOpTurnEventStateVtableSlotD4 @ 0x005D7190` (`thunk @ 0x0040691F`),
      - `NoOpTurnEventStateVtableSlotFC @ 0x005DBD10` (`thunk @ 0x00408724`).
    - strategic-map forwarders:
      - `InvokeStrategicMapViewMethod5C @ 0x005D7F70` (`thunk @ 0x00401ED8`),
      - `InvokeStrategicMapViewMethod60 @ 0x005D7F90` (`thunk @ 0x004027F2`),
      - `InvokeStrategicMapViewMethod68 @ 0x005DC180` (`thunk @ 0x004094E9`),
      - `InvokeStrategicMapViewMethod70 @ 0x005DC1C0` (`thunk @ 0x004098B8`).
    - mixed flow helper:
      - `HandleGlobalMapNationContextSelection @ 0x005DD180` (`thunk @ 0x00407BDA`).
  - Code-confirmed behavior:
    - no-op slots are direct returns,
    - strategic-map helpers are direct vtable forwards (`+0x5C/+0x60/+0x68/+0x70`),
    - `0x005DD180` refreshes map view `0x24F9` when selected nation matches current state, otherwise forwards to map context helper (`FUN_00503AC0`).

106. Renamed repetitive dialog-factory slot handlers with slot-accurate names (low-risk):
  - Renamed:
    - `HandleTurnEventDialogFactorySlot70 @ 0x005D6CD0` (`thunk @ 0x004064BA`),
    - `HandleTurnEventDialogFactorySlot74 @ 0x005D6D70` (`thunk @ 0x00407EBE`),
    - `HandleTurnEventDialogFactorySlot78 @ 0x005D6E50` (`thunk @ 0x00408611`),
    - `HandleTurnEventDialogFactorySlot7C @ 0x005D6F10` (`thunk @ 0x00405902`),
    - `HandleTurnEventDialogFactorySlot80 @ 0x005D6FD0` (`thunk @ 0x00402608`).
  - Code-confirmed behavior:
    - all routes resolve dialog object through factory manager and touch GOLD widget state;
    - slot `0x70` invokes object method `+0x9C`,
    - slots `0x74..0x80` run the same commit/refresh chain (`+0x1A0,+0x1AC,+0xA0,+0x1C`).
  - Practical conclusion:
    - improved readability for five formerly generic handlers while keeping naming conservative (slot-based).

107. Closed all remaining unresolved entries in `PTR_LAB_0066F120` with conservative slot-anchored names:
  - Materialized missing thunk functions:
    - `thunk_HandleTurnEventVtableSlot88BuildStatusText @ 0x004017B7`,
    - `thunk_HandleTurnEventVtableSlotA0SyncStatusPanel @ 0x004094F8`.
  - Renamed previously generic targets:
    - `HandleTurnEventVtableSlot08ConditionalDispatch @ 0x00485E90` (`thunk @ 0x00407C57`),
    - `HandleTurnEventVtableSlot24CopyPayloadBuffer @ 0x00415CE0` (`thunk @ 0x00405C59`),
    - `HandleTurnEventVtableSlot2CInitializeHotKeyDialog @ 0x005DCAA0` (`thunk @ 0x00406514`),
    - `HandleTurnEventVtableSlot40RefreshGoldDialog @ 0x005D57B0` (`thunk @ 0x00404C91`),
    - `HandleTurnEventVtableSlot60ActivateMainDialog @ 0x005DA040` (`thunk @ 0x004025A9`),
    - `HandleTurnEventVtableSlot88BuildStatusText @ 0x005D8980` (`thunk @ 0x004017B7`),
    - `HandleTurnEventVtableSlotA0SyncStatusPanel @ 0x005D8CC0` (`thunk @ 0x004094F8`).
  - Added plate comments for all renamed non-trivial target handlers above.
  - Verification:
    - reran `dump_vtable_entries_66f120.py`; all 64 entries now resolve to named thunk functions with no `<no_function>` gaps.
  - Practical conclusion:
    - `PTR_LAB_0066F120` is now fully materialized and named end-to-end, giving a clean base for next low-hanging turn-event ingress tracing.

108. Applied low-risk thunk-to-target inference and naming consistency cleanup:
  - Renamed a residual inconsistent thunk prefix:
    - `thunk_HandleTurnEvent7DD_RefreshOrderStatusPanelsAndIcons @ 0x004032DD` (from `ThunkHandle...`).
  - Inferred and renamed `FUN_*` targets from already-named direct thunks:
    - `ResetUiInputCaptureState @ 0x0048B700` (via `thunk_ResetUiInputCaptureState @ 0x00408A5D`),
    - `DispatchUiMouseMoveToChildren @ 0x0048C450` (via `thunk_DispatchUiMouseMoveToChildren @ 0x0040723E`),
    - `LoadUiStringResourceByGroupAndIndex @ 0x004994C0` (via `thunk_LoadUiStringResourceByGroupAndIndex @ 0x00401E7E`).
  - Added plate comments for all three target functions above.
  - Practical conclusion:
    - improved naming coherence in UI/input/resource helper surface using strictly wrapper-derived evidence.

109. Completed bulk low-hanging thunk prefix normalization in map/city/university wrapper cluster:
  - Ran scripted rename normalization from `Thunk*` to `thunk_*` across wrapper-style functions.
  - Result:
    - `180` functions renamed,
    - `0` skips/conflicts,
    - post-check confirms `count=0` remaining functions with `Thunk` prefix.
  - Practical conclusion:
    - callgraph/search consistency is substantially improved with zero semantic changes (naming-only pass).

110. Entry-point CRT startup helper surface renamed with high-confidence behavior labels:
  - Renamed core `entry()` helper callees:
    - `InitializeCrtHeapSubsystem @ 0x005EDE90`,
    - `InitializeCrtThreadDataTls @ 0x005ED740`,
    - `InitializeLowIoHandleTable @ 0x005F2420`,
    - `InitializeMultiByteCodePageFromLocale @ 0x005EB1F0`,
    - `SetMultiByteCodePageLocked @ 0x005EAEE0`,
    - `BuildAnsiEnvironmentBlockCopy @ 0x005F22C0`,
    - `BuildArgvFromCommandLine @ 0x005F1E10`,
    - `BuildEnvpArrayFromEnvironmentBlock @ 0x005F1D20`,
    - `IsLeadByteInCurrentCodePage @ 0x005F1C70`,
    - `CheckMultibyteCharacterClass @ 0x005F1CE0`,
    - `InitializeWinmmImportBindings @ 0x00707081`,
    - `ExitProcessWithCrtCleanup @ 0x005E9B90`,
    - `RunCrtExitHandlersAndTerminate @ 0x005E9BF0`,
    - supporting allocator helper `AllocateCrtHeapRegionDescriptor @ 0x005EDF40`.
  - Added plate comments for startup-critical helpers above.
  - Verification:
    - forced re-decompile of `entry @ 0x005E98B0` now reads as a coherent startup chain with these helper names inlined.
  - Practical conclusion:
    - main game entrypoint path is now substantially clearer and easier to extend into deeper lifecycle analysis.

111. Extended main lifecycle readability by renaming MFC state/setup/cleanup helpers:
  - Renamed dispatcher-adjacent framework helpers:
    - `GetOrCreateMfcModuleThreadState @ 0x00623886`,
    - `InitializeMfcAppStateFromEntryArgs @ 0x00624E73`,
    - `CleanupMfcAppStateAndHooks @ 0x00626C7D`.
  - Renamed newly surfaced sub-helpers from that flow:
    - `InitializeMfcAppPathResources @ 0x00624ED6`,
    - `InstallMfcThreadMessageHooks @ 0x006061FF`,
    - `CopyPathTailComponent @ 0x00624FF3`.
  - Added/updated plate comments for all six functions above.
  - Verification:
    - forced re-decompile of `DispatchMfcAppLifecycle @ 0x0060D3FC` now shows fully readable helper names in setup/teardown paths.
  - Practical conclusion:
    - entrypoint-to-framework transition now has named primitives for module state, app path resource bootstrap, hook install, and cleanup.

112. Low-hanging Windows UI spawn/registration wrappers renamed from import-driven xref scan:
  - Added scripted import-caller surface scan:
    - `scripts/find_windowing_callers.py` (targets USER32/MFC-facing imports like `CreateWindowExA`, `RegisterClassA`, `ShowWindow`, `DefWindowProcA`, `GetMessageA`, etc.).
  - Renamed core window creation/class registration helpers:
    - `CreateWindowExWithPreCreateHook @ 0x00608115`,
    - `RegisterWindowClassIfNeeded @ 0x00608892`,
    - `EnsureCreateWindowCbtHook @ 0x00608040`,
    - `ReleaseCreateWindowCbtHook @ 0x0060808C`,
    - `HandleDialogInitMessage @ 0x00604B68`,
    - `CreateDialogIndirectAndAttach @ 0x00604E5E`.
  - Renamed direct window-proc/show/position/destroy wrappers:
    - `DispatchWindowMessageToPrevProcOrDefault @ 0x00608467`,
    - `ShowWindowOrForwardToSite @ 0x006074F9`,
    - `SetWindowPosOrForwardToSite @ 0x006074AA`,
    - `UpdateWindowLongMaskedAndRefresh @ 0x0060785A`,
    - `DestroyWindowOrForwardToSite @ 0x0060841A`.
  - Renamed handle-map attachment primitives used by destroy/create paths:
    - `GetOrCreateMfcHandleMap @ 0x00607ABF`,
    - `DetachWindowHandleFromMap @ 0x00607BAC`,
    - `LookupHandleMapEntryByHwnd @ 0x00603516`.
  - Added plate comments for all functions above.
  - Practical conclusion:
    - this gives a concrete, readable “spawn window” chain from class registration through create-hook attach/detach and teardown.

113. Message-loop/help/DDE Windows-interface helpers renamed (DLL/API-facing behavior):
  - Renamed message pump and modal/help loop handlers:
    - `PumpMfcThreadMessageCore @ 0x0060694F`,
    - `DispatchPendingMessagesWithoutTranslate @ 0x0060A073`,
    - `RunModalLoopWithIdleMessages @ 0x0060A60A`,
    - `EnterFrameContextHelpMode @ 0x00619539`,
    - `DispatchContextHelpTrackingMessage @ 0x006197F7`,
    - `UpdateStatusBarMessageFromCommand @ 0x0061DB87`,
    - `GetTopLevelFrameFromCandidate @ 0x006093F3`,
    - `ActivateViewAndRefreshFrameStatus @ 0x0061419F`.
  - Renamed DDE/shell command bridge:
    - `HandleShellDdeExecuteCommand @ 0x0061A2EF` (parses `[open]`, `[print]`, `[printto]` command strings and dispatches app/frame actions).
  - Renamed tooltip relay helper:
    - `RelayMouseEventToTooltipWindow @ 0x005FADDB`.
  - Added plate comments for all functions above.
  - Verification:
    - reran `find_windowing_callers.py`; top multi-import caller cluster now resolves to descriptive names instead of `FUN_*`.
  - Practical conclusion:
    - Windows API ingress/egress points for window spawn, message pumping, context help, tooltip relay, and shell DDE commands are now much easier to trace.

114. Closed all remaining small `FUN_*` single-import wrappers (`SendMessageA`, `<=80` insns):
  - Verification baseline:
    - `scripts/find_small_single_import_fun.py` reported `count=27` candidates.
  - Renamed wrappers (high-confidence message semantics / conservative message-ID naming):
    - `SelectListBoxStringExactIfPresent @ 0x00618EA6`,
    - `SendControlMessages407And408 @ 0x005E64BE`,
    - `GetOrSetListBoxCurrentSelection @ 0x00618F94`,
    - `GetOrSetComboBoxCurrentSelection @ 0x00618FD6`,
    - `FetchListBoxItemTextIntoTempBuffer @ 0x0061E9BA`,
    - `GetOrSetButtonCheckStateClamped @ 0x00618D0F`,
    - `CopyListBoxItemDataStructByIndex @ 0x004805E6`,
    - `DispatchReflectedControlMessageOrFallback @ 0x00609C37`,
    - `SelectComboStringOrReadEditText @ 0x00618F43`,
    - `SetCommandCheckStateOnButtonOrMenu @ 0x00606DDD`,
    - `SyncTripleSelectionStateViaMessage400 @ 0x00482300`,
    - `MoveListBoxEntryPreserveItemData @ 0x005E5661`,
    - `GetDialogControlIdAndFillCommandContext @ 0x0060852E`,
    - `SelectComboStringOrGetEditText @ 0x00618EC3`,
    - `HideFocusedComboDropDownUnlessWithin @ 0x00614504`,
    - `BroadcastMessageToChildWindowsRecursive @ 0x00609550`,
    - `QueryParentWithMessage466 @ 0x005FFC15`,
    - `ValidateNumericLimitAndApplyToEditControl @ 0x006191F9`,
    - `QueryParentWithMessage464OrFallback @ 0x005FF7AC`,
    - `GetOrSetRadioGroupCheckedIndex @ 0x00618D61`,
    - `BroadcastFrameActivationState @ 0x0061CD09`,
    - `DispatchMouseWheelToFocusHierarchy @ 0x0061E63B`,
    - `ForwardSystemCommandToActiveFramePreserveFocus @ 0x00609A6A`,
    - `DispatchContextMessage365OrSendCommandE147 @ 0x006193C5`,
    - `HandleFrameActivationStateTransition @ 0x0061CC4B`,
    - `PaintListBoxItemFocusRect @ 0x005E56F2`,
    - `DispatchNegativeCommandRangeToFrameHandlers @ 0x005FFD49`.
  - Verification:
    - reran `scripts/find_small_single_import_fun.py`; now `count=0`.
  - Practical conclusion:
    - all remaining tiny/small single-import message wrappers were converted from `FUN_*` into actionable UI/control names.

115. Completed next-layer Windows import-caller cleanup (`find_windowing_callers.py` one-import tail):
  - Renamed one-import windowing callers surfaced after step 114:
    - `ApplyDialogSelectionToNationState @ 0x004140F0`,
    - `UpdateMapCursorFromSelectionContext @ 0x0048C250`,
    - `EnsureChildResourceWindowAndNotify @ 0x0048DE00`,
    - `DestroyChildResourceWindowAndDetach @ 0x0048E2A0`,
    - `PopulateListBoxFromDelimitedText @ 0x0049BD90`,
    - `AdvanceCivilianTerrainSelectionStep @ 0x004FC630`,
    - `InitializeDialogEditControlsAndLimits @ 0x0054E730`,
    - `UpdateMapCursorForTileAndAction @ 0x005958B0`,
    - `UpdateHexGridHoverCursorAndHighlight @ 0x005A8D40`,
    - `QueryParentWithMessages464And465OrFallback @ 0x005FF69E`,
    - `HandleFileDialogCustomMessages @ 0x005FFEB1`,
    - `HandleMessageFilterAndMaybeSendCommandE146 @ 0x006067A2`,
    - `DestroyMfcWindowAndDetachThreadState @ 0x006082F1`,
    - `RunWinHelpAfterCancelModeBroadcast @ 0x00608A2B`,
    - `RepositionChildControlsByIdRange @ 0x0060986B`,
    - `CenterWindowWithinOwnerOrWorkArea @ 0x0060A27D`,
    - `UpdateDialogChildCommandUiStates @ 0x0060A4D5`,
    - `GetMouseWheelScrollLines @ 0x00614CFA`,
    - `RecalculateScrollBarsAndLayout @ 0x00615778`,
    - `HandleScrollWheelAndUpdateWindow @ 0x00615A34`,
    - `ScrollByCommandAndUpdateWindow @ 0x00615B58`,
    - `PopulateListBoxFromLinkedItemCollection @ 0x00619E4E`,
    - `SwitchActiveFrameAndNotifyHandlers @ 0x0061D4B8`,
    - `ToggleOverlappingWindowSetVisibility @ 0x0061E1FE`,
    - `DispatchUiStatePacketByOpcode @ 0x00622CB3`.
  - Verification:
    - reran `scripts/find_windowing_callers.py`; no remaining one-import `FUN_*` entries in this Windows-facing set.
  - Practical conclusion:
    - low-hanging user32/mfc interface wrappers around help, scroll, activation, layout, dialog-proc routing, and cursor-policy code are now named.

116. Closed thunk-derived target rename seam (`named thunk -> FUN_* target` inference):
  - Verification baseline:
    - `scripts/find_fun_targets_from_named_thunks.py` reported `19` `FUN_*` targets with conflict count `0`.
  - Renamed inferred targets:
    - `CityViewProductionMethod_00406951 @ 0x00429450`,
    - `NumericEntryMethod_00409A39 @ 0x00429530`,
    - `CityViewProductionMethod_004042AF @ 0x0048A4A0`,
    - `CityViewProductionMethod_00405F9C @ 0x0048A500`,
    - `CityViewProductionMethod_00403A94 @ 0x0048A530`,
    - `CityViewProductionMethod_00401E1F @ 0x0048A570`,
    - `CityViewProductionMethod_00401834 @ 0x0048A650`,
    - `CityViewProductionMethod_00403A03 @ 0x0048A670`,
    - `CityViewProductionMethod_00404FCF @ 0x0048A6F0`,
    - `CityViewProductionMethod_0040424B @ 0x0048AFD0`,
    - `CityViewProductionMethod_00401267 @ 0x0048C1E0`,
    - `NumericEntryMethod_00402A9A @ 0x004906D0`,
    - `NumericEntryMethod_00401E6F @ 0x00490AA0`,
    - `NumericEntryMethod_00407CCA @ 0x00490AD0`,
    - `NumericEntryMethod_0040465B @ 0x00490C10`,
    - `NumericEntryMethod_00406D0C @ 0x00491040`,
    - `NumericEntryMethod_00407A7C @ 0x004912B0`,
    - `RefreshUniversityAdvancedStatus @ 0x004D05E0`,
    - `UniversityDialogMethod_00405623 @ 0x00572BB0`.
  - Verification:
    - reran `scripts/find_fun_targets_from_named_thunks.py`; now `candidate_count=0`, `conflict_count=0`.
  - Practical conclusion:
    - eliminated another dense low-risk pocket of `FUN_*` by promoting stable thunk-derived naming evidence.

117. Post-pass low-hanging verification sweep (no residuals in targeted seams):
  - Reran wrapper/thunk verification scripts:
    - `scripts/find_small_single_import_fun.py` -> `count=0`,
    - `scripts/find_windowing_callers.py` -> no remaining one-import `FUN_*` candidates,
    - `scripts/find_fun_wrapper_candidates.py` -> `candidate_count=0`,
    - `scripts/find_fun_targets_from_named_thunks.py` -> `candidate_count=0`,
    - `scripts/list_vtable66f120_unresolved_after_rename.py` -> empty unresolved list.
  - Practical conclusion:
    - current low-hanging wrapper surface around entry/MFC/windowing/thunk propagation has been materially exhausted for these scripted heuristics; next gains likely require deeper semantic passes rather than pure wrapper uplift.

118. City/production dialog spawn chain uplift (Windows API window-open path):
  - Trigger:
    - investigated user-observed flow “clicking building in city/production opens a new window/dialog”.
  - Renamed core modal creation pipeline around dialog spawn:
    - `InitializeDialogTemplateFromId @ 0x006050D0`,
    - `ResolveDialogOwnerWindowForModalCreate @ 0x00605144`,
    - `CleanupDialogModalCreateState @ 0x0060517B`,
    - `RunDialogModalFromTemplate @ 0x006051B9`,
    - `CreateDialogIndirectWithDefaultModule @ 0x00604E4C`,
    - `CreateDialogIndirectWithOwnerFallback @ 0x00604DDD`,
    - `CreateDialogByResourceNameAndAttach @ 0x00604E08`,
    - `CreateDialogFromResourceHandle @ 0x00604DA4`,
    - `CreateDialogFromResourceNameAndOwner @ 0x00604D42`.
  - Renamed template initializer/modal wrappers used by this path:
    - `InitializeDialogTemplateE0 @ 0x005DEE50`,
    - `ShowDialogTemplateE0ModalAndReleaseCapture @ 0x00498CC0`,
    - `ShowDialogTemplate64Modal @ 0x00413700`,
    - `PrepareAndCreateDialogFromTemplateResource @ 0x0049D360`,
    - `LoadAndPreviewDibFromDialogInput @ 0x004143B0`,
    - `InitializeDialogTemplateBaseState @ 0x00480750`,
    - `InitializeDialogTemplate104WithRegionState @ 0x00480A10`,
    - `InitializeDialogTemplateA1WithTripleTextState @ 0x004813A0`,
    - `InitializeDialogTemplateA7WithSharedText @ 0x00481770`,
    - `InitializeDialogTemplateABWithDualTextState @ 0x00481B30`,
    - `InitializeDialogTemplateAEWithDualTextState @ 0x00481DC0`,
    - `InitializeDialogTemplateB1WithSharedText @ 0x00482050`,
    - `InitializeDialogTemplateD0WithTextState @ 0x0049BCD0`,
    - `SelectEntryWithDialog7801AndInvokeHandler @ 0x0061A8DD`.
  - Renamed stale thunk wrappers to match new target names:
    - `thunk_ShowDialogTemplateE0ModalAndReleaseCapture @ 0x004028D3`,
    - `thunk_InitializeDialogTemplateE0 @ 0x00407450`,
    - `thunk_InitializeDialogTemplateBaseState @ 0x00403698`,
    - `thunk_InitializeDialogTemplateA1WithTripleTextState @ 0x0040713A`,
    - `thunk_InitializeDialogTemplateD0WithTextState @ 0x00408B2F`.
  - Added plate comments to key non-trivial functions:
    - `RunDialogModalFromTemplate @ 0x006051B9`,
    - `PrepareAndCreateDialogFromTemplateResource @ 0x0049D360`,
    - `InitializeDialogTemplateFromId @ 0x006050D0`,
    - `CreateDialogIndirectWithOwnerFallback @ 0x00604DDD`,
    - `InitializeDialogTemplateE0 @ 0x005DEE50`,
    - `ShowDialogTemplateE0ModalAndReleaseCapture @ 0x00498CC0`.
  - Practical conclusion:
    - the dialog/window-open plumbing used by city/production-style click flows is now named end-to-end at the modal create boundary, making further semantic mapping from click handlers to concrete dialog templates much faster.

119. City/production click-flow continuation: template mapping + method-family semantic uplift:
  - Mapped dialog-template constructor surface from `InitializeDialogTemplateFromId` callers:
    - added `scripts/list_dialog_template_constructor_calls.py`,
    - extracted `23` constructor callers with template IDs and vtable anchors,
    - confirmed dialog-template IDs used in this cluster: `0x64, 0x98, 0xA1, 0xA7, 0xAB, 0xAD, 0xAE, 0xB1, 0xC2, 0xD0, 0xD2, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xFA, 0xFB, 0x104, 0x7801`.
  - Concrete template/action mapping gain:
    - `0xA1` path is now code-confirmed as HotKey-dialog initialization via:
      - `HandleTurnEventVtableSlot2CInitializeHotKeyDialog -> thunk_InitializeHotKeyDialogTemplateA1WithTripleTextState -> InitializeHotKeyDialogTemplateA1WithTripleTextState -> RunDialogModalFromTemplate`.
    - renamed:
      - `InitializeHotKeyDialogTemplateA1WithTripleTextState @ 0x004813A0` (from generic A1 template name),
      - `thunk_InitializeHotKeyDialogTemplateA1WithTripleTextState @ 0x0040713A`.
  - City production method-family semantic renames (formerly `CityViewProductionMethod_00xxxx`):
    - `GetCityProductionControllerField60 @ 0x00429450`,
    - `DetachActiveCityProductionChildIfMatches @ 0x0048A4A0`,
    - `IsCurrentActiveCityProductionView @ 0x0048A500`,
    - `CanStartCityProductionActionFalse @ 0x0048A530`,
    - `ActivateCityProductionViewIfAllowed @ 0x0048A570`,
    - `HandleCityProductionNoOp @ 0x0048A650`,
    - `DispatchCityProductionAction1A @ 0x0048A670`,
    - `DispatchCityProductionAction1B @ 0x0048A6F0`,
    - `FindCityProductionChildByWindowHandle @ 0x0048AFD0`,
    - `RefreshCityProductionViewStateFromContext @ 0x0048C1E0`.
  - Thunk coherence updates for the same family:
    - `thunk_GetCityProductionControllerField60 @ 0x00406951`,
    - `thunk_DetachActiveCityProductionChildIfMatches @ 0x004042AF`,
    - `thunk_IsCurrentActiveCityProductionView @ 0x00405F9C`,
    - `thunk_CanStartCityProductionActionFalse @ 0x00403A94`,
    - `thunk_ActivateCityProductionViewIfAllowed @ 0x00401E1F`,
    - `thunk_HandleCityProductionNoOp @ 0x00401834`,
    - `thunk_DispatchCityProductionAction1A @ 0x00403A03`,
    - `thunk_DispatchCityProductionAction1B @ 0x00404FCF`,
    - `thunk_FindCityProductionChildByWindowHandle @ 0x0040424B`,
    - `thunk_RefreshCityProductionViewStateFromContext @ 0x00401267`.
  - Additional vtable cleanup from city-production dialog controller table (`0x00652A80`):
    - added `scripts/dump_vtable_region_652aa4.py`,
    - materialized missing functions via `scripts/materialize_city_production_dialog_vtable_no_functions.py`:
      - `thunk_AssertCityProductionGlobalStateInitialized @ 0x00401E2E` -> `AssertCityProductionGlobalStateInitialized @ 0x00429470`,
      - `thunk_NoOpCityProductionDialogMethod @ 0x00406EB5` -> `NoOpCityProductionDialogMethod @ 0x0048E9C0`.
    - renamed adjacent dialog-picture helpers:
      - `SetCityProductionDialogPictureRectAndMaybeRefresh @ 0x0048E7D0`,
      - `thunk_SetCityProductionDialogPictureRectAndMaybeRefresh @ 0x00403C60`,
      - `NoOpCityProductionDialogPictureHook @ 0x0048E9E0`,
      - `thunk_NoOpCityProductionDialogPictureHook @ 0x004068D4`.
  - WM_COMMAND/control-tag evidence in city production dialog path:
    - `OpenCityViewProductionDialog` binds control tags `'okay'/'cncl'` to action tag `0x22` and sets OK command id `0xBC7`.
    - `ApplyCityProductionDialogChanges` commits changes only on action `'okay'` (`0x6F6B6179`), otherwise applies cancel/reset path.
  - Practical conclusion:
    - city/production “click -> open window/dialog” flow now has both the modal-spawn boundary and the city-production method-table semantics named, with concrete control/action markers (`'okay'`, `'cncl'`, `0x22`, `0xBC7`) captured for next control-ID/WM_COMMAND routing pass.

120. Template-constructor cleanup pass (remaining `FUN_*` in dialog-init cluster):
  - Trigger:
    - residual constructor helpers discovered in `list_dialog_template_constructor_calls.py` still carried `FUN_*` names despite explicit template IDs in decompilation.
  - Renamed constructor helpers by template id:
    - `InitializeDialogTemplateC2WithTextState @ 0x0047CFD0`,
    - `InitializeDialogTemplateD2WithTextState @ 0x0047D1C0`,
    - `InitializeDialogTemplateDBWithTextState @ 0x0047D360`,
    - `InitializeDialogTemplateDCBaseState @ 0x0047D470`,
    - `InitializeDialogTemplateDDPictureState @ 0x0047D540`,
    - `InitializeDialogTemplateDEWithTextState @ 0x0047DBA0`,
    - `InitializeDialogTemplateDFBaseState @ 0x0047DCE0`,
    - `InitializeDialogTemplateFAWithTextState @ 0x0047DE40`,
    - `InitializeDialogTemplateFBWithDualTextState @ 0x0047DFD0`,
    - `InitializeDialogTemplateADWithTextState @ 0x0047F450`,
    - `InitializeDialogTemplate98WithSharedText @ 0x005E1BC0`,
    - `InitializeFileDialogTemplateBaseState @ 0x005FF46F` (template id `0`, file-dialog callback path).
  - Renamed associated thunk wrappers:
    - `thunk_InitializeDialogTemplateC2WithTextState @ 0x0040428C`,
    - `thunk_InitializeDialogTemplateDBWithTextState @ 0x004087C9`,
    - `thunk_InitializeDialogTemplateDCBaseState @ 0x00405F97`,
    - `thunk_InitializeDialogTemplateDDPictureState @ 0x00404A4D`,
    - `thunk_InitializeDialogTemplateDEWithTextState @ 0x0040545C`,
    - `thunk_InitializeDialogTemplateDFBaseState @ 0x0040147E`,
    - `thunk_InitializeDialogTemplateFBWithDualTextState @ 0x00404E44`,
    - `thunk_InitializeDialogTemplate98WithSharedText @ 0x00401393`.
  - Added plate comment:
    - `InitializeFileDialogTemplateBaseState @ 0x005FF46F`.
  - Verification:
    - reran `scripts/list_dialog_template_constructor_calls.py`; constructor-call map now resolves all `23` entries to descriptive names (no residual `FUN_*` in this template-init surface).
  - Practical conclusion:
    - constructor-level dialog/template initialization surface is now consistently named, reducing remaining ambiguity when tracing city/production click handlers into modal window creation paths.

121. Dialog-launch caller semantics uplift (city/production-adjacent modal prompts):
  - Traced direct callers of template-thunk constructors via xrefs:
    - `thunk_InitializeDialogTemplateC2WithTextState` callsite in `ShowCityViewSelectionDialog`,
    - `thunk_InitializeDialogTemplateDBWithTextState` callsite in `ShowNationSelectDialogAndRedispatchCurrentTurnEvent`,
    - `thunk_InitializeDialogTemplateDCBaseState` callsite in `HandleDialogResultAndPostCommand100`,
    - `thunk_InitializeDialogTemplateDDPictureState` callsites in DIB preview flow,
    - `thunk_InitializeDialogTemplateDEWithTextState` callsite in nation-state apply flow,
    - `thunk_InitializeDialogTemplateDFBaseState` callsite in DIB input flow,
    - `thunk_InitializeDialogTemplateFBWithDualTextState` callsite in settings/AutoRes prompt,
    - `thunk_InitializeDialogTemplate98WithSharedText` callsite in low-disk-space prompt.
  - Renamed previously generic caller functions:
    - `ShowSelectedDibInTemplateDDDialog @ 0x00413A50` (from `FUN_00413A50`),
    - `ShowAutoResolutionDialogIfNeeded @ 0x00415090` (from `FUN_00415090`),
    - `WarnLowDiskSpaceAndConfirmContinue @ 0x00415760` (from `FUN_00415760`).
  - Added plate comments:
    - `ShowSelectedDibInTemplateDDDialog @ 0x00413A50`,
    - `ShowAutoResolutionDialogIfNeeded @ 0x00415090`,
    - `WarnLowDiskSpaceAndConfirmContinue @ 0x00415760`.
  - Practical conclusion:
    - the remaining modal-prompt launch points around the same constructor family are now semantically named, improving control-flow readability from command handlers into concrete dialogs (city picker, nation select, DIB preview, AutoRes, low-disk warning).

122. City building-click dialog class-vtable uplift (`TBuildingExpansionView` / `TArmoryView` / `TEngineerDialog`):
  - Trigger:
    - continued low-hanging sweep from city/production click flow into adjacent window/dialog class vtables.
  - Added mapping/materialization scripts:
    - `scripts/dump_vtable_region_652b10.py`,
    - `scripts/materialize_vtable_652b10_no_functions.py`,
    - `scripts/dump_vtable_regions_armory_related.py`,
    - `scripts/materialize_armory_adjacent_no_functions.py`.
  - Class identity recovered from class-name virtuals:
    - `GetBuildingExpansionViewClassName @ 0x004CE500` (`"TBuildingExpansionView"`),
    - `GetArmoryViewClassName @ 0x004CED80` (`"TArmoryView"`),
    - `GetEngineerDialogClassName @ 0x004D0540` (`"TEngineerDialog"`).
  - Constructor/factory/destructor renames:
    - `CreateBuildingExpansionView @ 0x004CE480`,
    - `ConstructBuildingExpansionView @ 0x004CE520`,
    - `DestructBuildingExpansionViewAndMaybeFree @ 0x004CE550`,
    - `CreateArmoryView @ 0x004CECE0`,
    - `ConstructArmoryView @ 0x004CEDA0`,
    - `DestructArmoryViewAndMaybeFree @ 0x004CEDD0`,
    - `CreateEngineerDialog @ 0x004D04B0`,
    - `ConstructEngineerDialog @ 0x004D0560`,
    - `DestructEngineerDialogAndMaybeFree @ 0x004D0590`,
    - `DestructEngineerDialogBaseState @ 0x0048A9D0`,
    - `RenderEngineerDialogBackground @ 0x004D0650`.
  - Shared city-dialog base/utility surface renamed (replacing armory-only names that were too narrow):
    - `HandleCityDialogNoOpSlot14 @ 0x00485F70`,
    - `HandleCityDialogNoOpSlot18 @ 0x00485F90`,
    - `GetCityDialogFlagByte4 @ 0x0048A240`,
    - `SetCityDialogFlagByte4 @ 0x0048A260`,
    - `GetCityDialogValueDwordC @ 0x0048A2C0`,
    - `ForwardCityDialogParamToChildSlot44 @ 0x0048A310`,
    - `ForwardCityDialogParamToChildSlot48 @ 0x0048A380`,
    - `CanHandleCityDialogActionFalse @ 0x0048A480`,
    - `GetCityDialogValueDword10 @ 0x00415D50`,
    - `SetCityDialogValueDword10 @ 0x00415D70`,
    - `GetCityDialogValueViaChildSlot58 @ 0x0048B180`,
    - `GetCityDialogZeroValue @ 0x0048A550`,
    - `HandleCityDialogNoOpA @ 0x0048A690`,
    - `HandleCityDialogNoOpB @ 0x0048A6B0`,
    - `HandleCityDialogToggleCommandOrForward @ 0x0048E710`,
    - `InvalidateCityDialogRectRegion @ 0x0048B5F0`,
    - `CopyCityDialogStateFromSource @ 0x0048BEF0`,
    - `DestructCityDialogSharedBaseState @ 0x0048F250`,
    - `CloneCityDialogExtendedStateToNewInstance @ 0x0048F640`.
  - Additional class-specific behavior renames:
    - `HandleArmoryViewSelectionAndStepCommand @ 0x004CF350`,
    - `HandleArmoryViewCloseAndMaybePostCommand23F8 @ 0x004D0470`,
    - `CloneEngineerDialogStateToNewInstance @ 0x0048BFD0`,
    - `ForwardEngineerDialogCommandToChildSlot40 @ 0x0048A280`,
    - `CloseCityDialogChildrenAndReleaseSelf @ 0x0048B0B0`.
  - Registry/refcount helper renames used by dialog-state clone/destruct path:
    - `IncrementDialogResourceRefCountByShortIdInRegistry @ 0x0049A0B0`,
    - `DecrementDialogResourceRefCountByShortIdAndCleanup @ 0x0049A190`.
  - Thunk coherence:
    - renamed all newly materialized and affected wrappers in this cluster, including:
      - `thunk_GetBuildingExpansionViewClassName @ 0x00401113`,
      - `thunk_DestructBuildingExpansionViewAndMaybeFree @ 0x0040154B`,
      - `thunk_ConstructBuildingExpansionView @ 0x00407ACC`,
      - `thunk_ConstructArmoryView @ 0x0040677B`,
      - `thunk_GetEngineerDialogClassName @ 0x00409016`,
      - `thunk_DestructEngineerDialogAndMaybeFree @ 0x00409237`,
      - `thunk_ConstructEngineerDialog @ 0x00401A91`,
      - `thunk_CloneEngineerDialogStateToNewInstance @ 0x004082CE`,
      - `thunk_ForwardEngineerDialogCommandToChildSlot40 @ 0x00408657`,
      - `thunk_CloseCityDialogChildrenAndReleaseSelf @ 0x00408DB4`.
  - Added plate comments:
    - `HandleArmoryViewSelectionAndStepCommand @ 0x004CF350`,
    - `CloseCityDialogChildrenAndReleaseSelf @ 0x0048B0B0`,
    - `RenderEngineerDialogBackground @ 0x004D0650`,
    - `CreateArmoryView @ 0x004CECE0`.
  - Verification:
    - reran `scripts/dump_vtable_regions_armory_related.py`; all three related vtable regions now resolve to descriptive names (no `<no_function>` entries left in listed slots).

123. Local low-hanging closure pass in city-window range (`0x004CE000-0x004D0800`):
  - Added and ran `scripts/list_fun_range_4ce000_4d0800.py`.
  - Before pass:
    - `8` unresolved `FUN_*` entries in this range (`0x004CE480`, `0x004CE520`, `0x004CE550`, `0x004CECE0`, `0x004D04B0`, `0x004D0560`, `0x004D0590`, `0x004D0650`).
  - After class/vtable rename pass:
    - rerun produced `count=0` in the same range.
  - Practical conclusion:
    - city/building click-adjacent dialog object surface is now materially de-obfuscated, with factory/class identity, shared base methods, and event/render hooks all named for faster next-step tracing from WM_COMMAND/control tags into concrete behavior.

124. Full-slot vtable closure and dialog-assert helper naming:
  - Added and ran `scripts/dump_vtable_regions_armory_related_full.py` (32 slots each for `0x006528D8`, `0x00652B10`, `0x00652D60`).
  - Verification result:
    - all 96 inspected slots resolve to named thunks/functions (no `<no_function>` entries in these three class tables).
    - confirmed shared tail behavior across all three classes (slots 16..31) routes through common city-dialog/city-production helpers.
  - Renamed previously generic assert/invalidation helper pair used throughout city dialog error paths:
    - `SetGlobalUiInvalidationFlagAndReturnPrevious @ 0x00489A50`,
    - `TemporarilyClearAndRestoreUiInvalidationFlag @ 0x0049D620`,
    - `thunk_SetGlobalUiInvalidationFlagAndReturnPrevious @ 0x004090ED`,
    - `thunk_TemporarilyClearAndRestoreUiInvalidationFlag @ 0x004057A4`.
  - Forced redecompilation check:
    - `OpenCityViewProductionDialog @ 0x004CE5A0` now cleanly shows these helper names (instead of `thunk_FUN_*`) on Nil-Pointer/Failure branches.
  - Practical conclusion:
    - click-to-window code in the city/building dialog family now reads coherently end-to-end, with both class-vtable identities and repeated error-path utility calls semantically named.

125. Init-table materialization and low-hanging thunk cleanup in city/UI corridor:
  - Trigger:
    - while tracing dialog-template D0 callsites, identified data-driven init function pointers (`0x00692660` table) that still resolved to `<no_function>`/`FUN_*`.
  - Added scripts:
    - `scripts/dump_init_func_table_69266c.py`,
    - `scripts/materialize_init_table_692660_functions.py`,
    - `scripts/dump_window_49baa7.py`,
    - `scripts/dump_window_49c120.py`,
    - `scripts/list_thunk_fun_range_480000_4d2000.py`.
  - Materialized and renamed init-table function-pointer targets (selection):
    - `InitializeStaticDialogTemplateD0AndRegisterAtExit @ 0x0049BAA0`,
    - `CleanupStaticDialogTemplateD0AtExit @ 0x0049BAD0`,
    - `DestructStaticDialogTemplateD0Object @ 0x0049BAF0`,
    - global reset helpers:
      - `ResetGlobalPair6A1E20And6A1E24 @ 0x0049B9D0`,
      - `ResetGlobalQuad6A1E28To6A1E34 @ 0x0049BA10`,
      - `ResetGlobalQuad6A1E38To6A1E44 @ 0x0049BA40`,
      - `ResetGlobalDword6A1E18 @ 0x0049BA70`,
      - `ResetGlobalPair6A1E70And6A1E74 @ 0x0049BC00`,
      - `ResetGlobalPair6A1F38And6A1F3C @ 0x0049BC20`,
      - `ResetGlobalQuad6A1F18To6A1F24 @ 0x0049BC40`,
      - `ResetGlobalQuad6A1F28To6A1F34 @ 0x0049BC70`,
      - `ResetGlobalDword6A1E68 @ 0x0049BCA0`,
      - `ResetGlobalPair6A1F78And6A1F7C @ 0x0049BFF0`,
      - `ResetGlobalPair6A1FA8And6A1FAC @ 0x0049C010`,
      - `ResetGlobalQuad6A1F88To6A1F94 @ 0x0049C030`,
      - `ResetGlobalQuad6A1F98To6A1FA4 @ 0x0049C060`,
      - `ResetGlobalDword6A1F70 @ 0x0049C090`,
      - `InitializeGlobalPair6A1FE8And6A1FECDefault @ 0x0049C0C0`,
      - `InitializeGlobalPair6A1FC0And6A1FC4Default @ 0x0049C0F0`,
      - `UpdateGlobalWord6A2008FromScaled6A1FC0 @ 0x0049C120`,
      - `ResetGlobalPair6A1FD0And6A1FD4 @ 0x0049CAC0`,
      - `ResetGlobalPair6A2000And6A2004 @ 0x0049CAE0`,
      - `ResetGlobalQuad6A1FD8To6A1FE4 @ 0x0049CB00`,
      - `ResetGlobalQuad6A1FF0To6A1FFC @ 0x0049CB30`,
      - `ResetGlobalDword6A1FC8 @ 0x0049CB60`,
      - `ResetGlobalPair6A2020And6A2024 @ 0x0049D290`.
  - Additional semantic uplift from same pass:
    - `DestructCObArray @ 0x00601BDD`,
    - `DestructCObArrayAndMaybeFree @ 0x00601BC1`,
    - `SetCObArraySize @ 0x00601C14`,
    - `AllocateAndLinkBlockHead @ 0x00601B74`,
    - `FreeLinkedBlockChain @ 0x00601B94`,
    - `InitializeDirectSoundDeviceAndChannels @ 0x0049C970`,
    - `DispatchVfuncA0ToLinkedChildListSlot44 @ 0x0048C890`.
  - Thunk cleanup:
    - normalized former `thunk_FUN_*` wrappers to descriptive names (including `thunk_DestructCObArray*`, `thunk_InitializeDirectSoundDeviceAndChannels*`, and `thunk_DispatchVfuncA0ToLinkedChildListSlot44*`).
  - Added plate comments:
    - `InitializeStaticDialogTemplateD0AndRegisterAtExit @ 0x0049BAA0`,
    - `InitializeDirectSoundDeviceAndChannels @ 0x0049C970`,
    - `DispatchVfuncA0ToLinkedChildListSlot44 @ 0x0048C890`,
    - `DestructCObArray @ 0x00601BDD`.
  - Verification:
    - reran `scripts/list_thunk_fun_range_480000_4d2000.py`; `count=0`.
  - Practical conclusion:
    - this removes the remaining low-hanging `thunk_FUN_*` residue in the active city/UI work corridor and turns the nearby data-driven init function table into readable, traceable initialization logic.

126. Entry-startup helper rename pass (InitInstance callee cleanup):
  - Trigger:
    - startup call-graph around `InitializeImperialismApplicationInstance` still contained a dense pocket of `FUN_*`/`thunk_FUN_*` helpers despite core entry chain being mapped.
  - Renamed startup/InitInstance helpers:
    - `ParseAndDispatchCommandLineArguments @ 0x00622632`,
    - `ConstructCommandLineParseContext @ 0x00622690`,
    - `DestructCommandLineParseContext @ 0x0062271B`,
    - `UpdateAppInstallAndDataPaths @ 0x00623061`,
    - `LoadLanguageResourcesFromIrgFiles @ 0x004149A0`,
    - `LoadPrimaryDataLibraryWithErrorDialog @ 0x00499380`,
    - `LoadDataLibraryBySlotWithErrorDialog @ 0x004992A0`,
    - `ConstructDataLibraryLoadState @ 0x00498F60`,
    - `InitializeGlobalRuntimeSystemsFromConfig @ 0x0049DED0`,
    - `SetUiRuntimeContextAndActivateMain @ 0x00483340`,
    - `ApplyAutoResolutionModeAndPersist @ 0x004155B0`,
    - `ConstructGlobalUiRootControllerState @ 0x00486760`,
    - `ConstructSfxPlaybackSystemState @ 0x00593370`,
    - `SetGlobalDword6A2018 @ 0x0049CC40`,
    - `SetGlobalCallback6A7FACAndReturnPrevious @ 0x005E7A80`,
    - `CompareAnsiStringsWithMbcsAwareness @ 0x005E7980`,
    - `DispatchOptionalHandlerAtOffset80Slot3C @ 0x0061842F`,
    - `CleanupUiPacketQueueAndRegistryBranch @ 0x00622DFC`,
    - `CleanupFileAssociationShellCommandRegistryEntries @ 0x006246E9`,
    - `RunFileAssociationShellCommandCleanup @ 0x00623050`,
    - `GetObjectValueAtOffset98 @ 0x0061D89B`.
  - Thunk coherence updates:
    - `thunk_LoadLanguageResourcesFromIrgFiles @ 0x00402937`,
    - `thunk_InitializeGlobalRuntimeSystemsFromConfig @ 0x00405BA0`,
    - `thunk_SetUiRuntimeContextAndActivateMain @ 0x00401B77`,
    - `thunk_ApplyAutoResolutionModeAndPersist @ 0x00406FFA`,
    - `thunk_SetGlobalDword6A2018 @ 0x0040450C`,
    - `thunk_ConstructDataLibraryLoadState @ 0x00408710`,
    - `thunk_ConstructSfxPlaybackSystemState @ 0x0040923C`,
    - `thunk_ConstructGlobalUiRootControllerState @ 0x0040223E`.
  - Added plate comments:
    - `ParseAndDispatchCommandLineArguments @ 0x00622632`,
    - `LoadDataLibraryBySlotWithErrorDialog @ 0x004992A0`,
    - `LoadLanguageResourcesFromIrgFiles @ 0x004149A0`,
    - `InitializeGlobalRuntimeSystemsFromConfig @ 0x0049DED0`,
    - `CleanupFileAssociationShellCommandRegistryEntries @ 0x006246E9`.
  - Verification:
    - forced redecompilation of `InitializeImperialismApplicationInstance`; startup body now resolves these helpers by semantic names (no `thunk_FUN_*` residue in this call cluster).
  - Practical conclusion:
    - entrypoint/startup chain readability is materially improved beyond the top-level lifecycle names, enabling faster follow-up on resource/package load failures and pre-main UI initialization behavior.

127. Startup/turn-state low-hanging thunk closure (entrypoint-adjacent function naming pass):
  - Trigger:
    - although `InitializeImperialismApplicationInstance` was largely cleaned, key startup handlers and the `AdvanceGlobalTurnStateMachine` hot path still carried low-hanging `FUN_*`/`thunk_FUN_*` residue.
  - Renamed startup and MFC bridge helpers:
    - `LockMfcTempMaps @ 0x00606C67`,
    - `UnlockMfcTempMaps @ 0x00606C7C`,
    - `SetWindowTextOrDelegateToOwner @ 0x006073B4`,
    - `SetMfcThreadStateFlagDword30 @ 0x0061F45C`,
    - `GetMfcThreadStateFlagDword30 @ 0x0061F46B`.
  - Renamed turn-state/message dispatch core helpers:
    - `AssignStringSharedRefAndReturnThis @ 0x0049EB00`,
    - `GetByteFlagAtOffset8 @ 0x004A6DD0`,
    - `ConstructTurnEventPacketBase @ 0x00487820`,
    - `DispatchUiPacketWithTagNEXT @ 0x004F2930`,
    - `SyncNationField790FromLocalizationStateId @ 0x004F0590`,
    - `ShowTurnAlertsForActiveNation @ 0x00502B60`,
    - `ConfigureTurnResumeStateAndNationMask @ 0x00543120`,
    - `HandleTurnResumeStateTelemetry @ 0x00543280`,
    - `TrySaveGameAndMaybeShowFailureDialog @ 0x0054D4E0`,
    - `RefreshNavyOrderCycleAndClearReadyFlags @ 0x00557040`,
    - `RebuildNationRankingDataAndUiCache @ 0x0055B8E0`,
    - `SaveGameWithModeAndOptionalLabel @ 0x0056DA50`,
    - `RebuildMapContextAndGlobalMapState @ 0x0057C7C0`,
    - `UpdatePersistentTopTenNationScores @ 0x00581510`,
    - `RefreshNationAdvisorLabelStrings @ 0x00581C00`,
    - `ProcessTurnInstructionStreamAndFinalizePhase @ 0x00581E60`,
    - `RemoveNationSlotAndNotifyPeers @ 0x00581300`,
    - `ResetDualAudioCuePools @ 0x00593730`,
    - `PushCueToDualAudioCuePools @ 0x00593760`,
    - `SelectAndScheduleRandomAudioCue @ 0x00593790`,
    - `ConsumeFirstPendingAbilityUnlock @ 0x005B0C20`,
    - `DispatchLocalizedUiMessageWithTemplateA13A0 @ 0x005D5B00`,
    - `DispatchLocalizedUiMessageWithTemplate @ 0x005D5C40`,
    - `ReturnTrueStub @ 0x005DF8D0`,
    - `RefreshNationCivilianWorkOrdersForTurn @ 0x004DFD30`.
  - Thunk coherence updates:
    - renamed corresponding wrappers in this call corridor (`thunk_AssignStringSharedRefAndReturnThis`, `thunk_GetByteFlagAtOffset8`, `thunk_ConstructTurnEventPacketBase`, `thunk_DispatchUiPacketWithTagNEXT`, `thunk_SyncNationField790FromLocalizationStateId`, `thunk_ShowTurnAlertsForActiveNation`, `thunk_ConfigureTurnResumeStateAndNationMask`, `thunk_HandleTurnResumeStateTelemetry`, `thunk_TrySaveGameAndMaybeShowFailureDialog`, `thunk_RefreshNavyOrderCycleAndClearReadyFlags`, `thunk_RebuildNationRankingDataAndUiCache`, `thunk_SaveGameWithModeAndOptionalLabel`, `thunk_RebuildMapContextAndGlobalMapState`, `thunk_UpdatePersistentTopTenNationScores`, `thunk_RefreshNationAdvisorLabelStrings`, `thunk_ProcessTurnInstructionStreamAndFinalizePhase`, `thunk_RemoveNationSlotAndNotifyPeers`, `thunk_ResetDualAudioCuePools`, `thunk_PushCueToDualAudioCuePools`, `thunk_SelectAndScheduleRandomAudioCue`, `thunk_ConsumeFirstPendingAbilityUnlock`, `thunk_DispatchLocalizedUiMessageWithTemplateA13A0`, `thunk_DispatchLocalizedUiMessageWithTemplate`, `thunk_ReturnTrueStub`, `thunk_RefreshNationCivilianWorkOrdersForTurn`).
  - Added plate comments:
    - `LockMfcTempMaps @ 0x00606C67`,
    - `UnlockMfcTempMaps @ 0x00606C7C`,
    - `SetWindowTextOrDelegateToOwner @ 0x006073B4`,
    - `SetMfcThreadStateFlagDword30 @ 0x0061F45C`,
    - `GetMfcThreadStateFlagDword30 @ 0x0061F46B`,
    - `DispatchUiPacketWithTagNEXT @ 0x004F2930`,
    - `ShowTurnAlertsForActiveNation @ 0x00502B60`,
    - `RebuildMapContextAndGlobalMapState @ 0x0057C7C0`,
    - `ProcessTurnInstructionStreamAndFinalizePhase @ 0x00581E60`,
    - `DispatchLocalizedUiMessageWithTemplateA13A0 @ 0x005D5B00`.
  - Verification:
    - forced redecompilation confirms `HandleStartupCommand100` now resolves `LockMfcTempMaps/UnlockMfcTempMaps` directly.
    - forced redecompilation confirms `RunImperialismThreadMainLoop` now resolves `GetMfcThreadStateFlagDword30`.
    - forced redecompilation confirms `InitializeImperialismApplicationInstance` has no residual `FUN_*` in its direct callee list.
    - forced redecompilation confirms `AdvanceGlobalTurnStateMachine` no longer contains `thunk_FUN_*` callsites in the previously noisy state-transition cluster.
  - Practical conclusion:
    - startup-entry + immediate turn-state control flow is now materially cleaner for next-stage decomposition (state semantics, packet schema, and event producer tracing) without wrapper-noise slowdown.

128. Save/stream utility seam closure for turn-state follow-through:
  - Trigger:
    - after cleaning `AdvanceGlobalTurnStateMachine`, the next low-hanging readability bottleneck was a dense save/stream utility seam still surfaced as `FUN_*`/`thunk_FUN_*` in the state-finalization and save-label flow.
  - Renamed core utility wrappers used by turn/save paths:
    - `ConstructSharedStringFromCStrOrResourceId @ 0x00605950`,
    - `AssignStringSharedFromCStr @ 0x00605CCE`,
    - `AssignStringSharedFromRef @ 0x00605D0A`,
    - `FreeHeapBufferIfNotNull @ 0x00606FAF`,
    - `FormatStringWithVarArgsToSharedRef @ 0x005FF15E`,
    - `OpenBufferedStreamWithMode40 @ 0x005E9100`,
    - `ReadBufferedStreamLocked @ 0x005E9440`,
    - `CloseBufferedStreamAndReleaseResources @ 0x005E9010`,
    - `EnterStreamCriticalSection @ 0x005EDBC0`,
    - `LeaveStreamCriticalSection @ 0x005EDC30`,
    - `FreeHeapBlockWithAllocatorTracking @ 0x005E7F50`.
  - Renamed ranking/resource stream cluster:
    - `GetRankingTableStringBaseAtOffset28 @ 0x0055BA10`,
    - `LoadAndByteSwapRankingTableResource @ 0x0055BA30`,
    - `BuildNationRankingRowsForNation @ 0x0055BC10`,
    - `LoadTableResourceStreamByName @ 0x005DF430`,
    - `ReleaseResourceStreamIfNotNull @ 0x005DF6D0`,
    - `ReadResourceStreamIntoBufferAndAdvance @ 0x005DF700`,
    - `GetResourceStreamSize @ 0x005DF760`,
    - `BuildScenarioPathForModeAndIndex @ 0x005DFD70`.
  - Renamed save-path metadata helpers:
    - `GetShortAtOffset14OrInvalid @ 0x0055F0B0`,
    - `ApplyNationIndexedShortUpdateFromStream @ 0x005823E0`,
    - `BuildSavePathStringForMode @ 0x0056D660`,
    - `ReadScenarioIndexFromSaveHeader @ 0x0056D7D0`,
    - `TryGetFileMetadataForPath @ 0x005D4C10`,
    - `DeleteFileWithErrorReporting @ 0x005D4C40`,
    - `ShowSavedStatusDialogAndReturnAccepted @ 0x005E0030`,
    - `QueryFileMetadataWithFindFirst @ 0x0060B9EA`,
    - `DeleteFileOrReportLastError @ 0x0060B12C`.
  - Thunk coherence updates:
    - renamed corresponding wrappers including:
      - `thunk_GetRankingTableStringBaseAtOffset28 @ 0x00406A4B`,
      - `thunk_LoadAndByteSwapRankingTableResource @ 0x004023F6`,
      - `thunk_BuildNationRankingRowsForNation @ 0x00405A79`,
      - `thunk_LoadTableResourceStreamByName @ 0x004012E9`,
      - `thunk_ReleaseResourceStreamIfNotNull @ 0x00403670`,
      - `thunk_ReadResourceStreamIntoBufferAndAdvance @ 0x0040255E`,
      - `thunk_GetResourceStreamSize @ 0x004042AA`,
      - `thunk_BuildScenarioPathForModeAndIndex @ 0x004054C5`,
      - `thunk_GetShortAtOffset14OrInvalid @ 0x004055BA`,
      - `thunk_ApplyNationIndexedShortUpdateFromStream @ 0x004033A5`,
      - `thunk_BuildSavePathStringForMode @ 0x00409129`,
      - `thunk_ReadScenarioIndexFromSaveHeader @ 0x00408CEC`,
      - `thunk_TryGetFileMetadataForPath @ 0x004075E5`,
      - `thunk_ShowSavedStatusDialogAndReturnAccepted @ 0x00401F96`.
  - Added plate comments:
    - `ConstructSharedStringFromCStrOrResourceId @ 0x00605950`,
    - `BuildScenarioPathForModeAndIndex @ 0x005DFD70`,
    - `LoadTableResourceStreamByName @ 0x005DF430`,
    - `ReadResourceStreamIntoBufferAndAdvance @ 0x005DF700`,
    - `ShowSavedStatusDialogAndReturnAccepted @ 0x005E0030`,
    - `QueryFileMetadataWithFindFirst @ 0x0060B9EA`.
  - Verification:
    - forced redecompilation of `SaveGameWithModeAndOptionalLabel` now resolves stream/save helpers semantically (no `FUN_005E9***`/`FUN_00605***` residue in this path).
    - forced redecompilation of `ProcessTurnInstructionStreamAndFinalizePhase` now resolves core save-path utility calls by semantic names.
    - forced redecompilation of `RebuildNationRankingDataAndUiCache` now resolves ranking-table setup and heap-buffer cleanup through named helpers.
 - Practical conclusion:
    - turn-finalization and save/metadata handling paths are now substantially de-obfuscated, making the remaining work more about behavior semantics than wrapper-chasing.

129. Dynamic dispatcher producer low-hanging rename closure (`g_pUiRuntimeContext` `vfunc +0x4C` feeder set):
  - Trigger:
    - remaining high-frequency dynamic dispatcher producers still surfaced as `FUN_*` near the unresolved `0x3B6` ingress frontier.
  - Method:
    - executed scripted caller sweep `find_gctx_vfunc4c_calls_precise_v2.py`,
    - applied a batch address-rename transaction via `rename_turn_event_scheduler_batch_20260216.py` (idempotent, skip-safe),
    - forced redecompilation checks on the two highest-impact control functions in this branch.
  - Renamed dynamic dispatch producers and adjacent scheduler helpers:
    - `DispatchTurnEvent11F8WithNoPayload @ 0x004DAF00`,
    - `DispatchTurnEvent2103WithNationFromRecord @ 0x004DF5C0`,
    - `DispatchTurnEvent3B8AndWaitForCompletionFlag @ 0x0050D310`,
    - `RebuildGlobalMapStateAndMaybeDispatchTurnEvent3C0 @ 0x0050ED4D`,
    - `DispatchTurnEvent2134AndRefreshNationPanels @ 0x0057F3C0`,
    - `DispatchUiMouseMoveThenClearTurnEvent @ 0x00584B70`,
    - `InitializeBattleSetupAndMaybeDispatchTurnEventED8 @ 0x005A4790`,
    - `HandleCommand10AndPostTurnEvent7E0 @ 0x004FB990`,
    - `EnsureGameFlowStateAndPostTurnEvent5E5 @ 0x00544540`,
    - `ResetGameFlowStateAndPostTurnEvent5DC @ 0x00544F30`,
    - `ResetGameFlowStateAndPostTurnEvent5DCAlt @ 0x00545290`,
    - `ApplyJoinGameSelectionAndPostTurnEvent5E4 @ 0x00545320`,
    - `ApplyNationSelectionAndMaybePostTurnEvent5E4 @ 0x00577E40`,
    - `HandleTurnStateExitAndPostFollowupEventCode @ 0x005DB620`,
    - `HandleSetupDialogCommandTagsAndDispatchEvents @ 0x00576230`,
    - `ResetGameFlowPromptStateAndPostTurnEvent5E5 @ 0x00542520`,
    - `HandleTurnFlowStateTickOrPostTurnEvent5DC @ 0x0056D190`,
    - `ValidateGameFlowNameAndSelectionContext @ 0x00544FC0`,
    - `ValidateAndPrepareGameFlowNameForDispatch @ 0x00544FF0`,
    - `OpenJoinGameRuntimeSelectionAndStartSession @ 0x005E3C20`,
    - `ShowCountrySelectionPromptAndReturnNationId @ 0x00508910`.
  - Added plate comments:
    - `RebuildGlobalMapStateAndMaybeDispatchTurnEvent3C0 @ 0x0050ED4D`,
    - `ApplyNationSelectionAndMaybePostTurnEvent5E4 @ 0x00577E40`,
    - `HandleTurnStateExitAndPostFollowupEventCode @ 0x005DB620`,
    - `HandleSetupDialogCommandTagsAndDispatchEvents @ 0x00576230`,
    - `ValidateAndPrepareGameFlowNameForDispatch @ 0x00544FF0`.
  - Verification:
    - batch rename result: `21 renamed, 0 missing, 0 failed`,
    - reran `find_gctx_vfunc4c_calls_precise_v2.py`; dynamic `+0x4C` producer list now resolves by semantic names at all newly renamed sites,
    - forced redecompilation of:
      - `HandleSetupDialogCommandTagsAndDispatchEvents`,
      - `HandleTurnStateExitAndPostFollowupEventCode`,
      now renders renamed callees directly (no residual `FUN_*` in this immediate scheduler seam).
  - Save-state note:
    - attempted program save via `save_program_codex.py`; Ghidra returned `Unable to lock due to active transaction` during this pass.

130. Additional event-status UI low-hanging rename uplift:
  - Trigger:
    - post-batch validation exposed two remaining high-traffic `FUN_*` routines in the same turn-event dispatch/status seam.
  - Renamed:
    - `RefreshTurnOrderStatusPanelTextsAndControls @ 0x005853F0`,
    - `HandleTurnEventViewportEdgeAutoScroll @ 0x0049E320`.
  - Added plate comments:
    - `RefreshTurnOrderStatusPanelTextsAndControls @ 0x005853F0`,
    - `HandleTurnEventViewportEdgeAutoScroll @ 0x0049E320`.
  - Verification:
    - forced redecompilation confirms both new names and shows expected behavior:
      - `0x005853F0` rebuilds/updates status strings and control states by current event code (`g_pUiRuntimeContext + 0x4`),
      - `0x0049E320` gates edge autoscroll to specific turn-event states (`0x7DD`, `0x3B8`, `0xED8`, `0xF3C`, `0x3C0`) and otherwise forwards to base mouse-move handler.
  - Follow-up note:
    - `PostTurnEventCodeMessage2420` caller scan still reports two `<no_function>` micro-islands (`0x0056AFA8`, `0x0056B04E`) that are currently boundary/materialization issues rather than remaining named-function gaps.

## Working Hypothesis
- Startup chain is now code-confirmed as:
  - `entry (0x005e98b0)`
  - `-> CallMfcAppLifecycleEntry (0x005fa7c2)`
  - `-> DispatchMfcAppLifecycle (0x0060d3fc)`
  - `-> InitializeAppDocTemplateManagerAndFlushPending (vtable +0x8C)`
  - `-> InitializeImperialismApplicationInstance (vtable +0x58)`
  - `-> RunImperialismThreadMainLoop (vtable +0x5C)`
  - `-> RunMfcThreadMessageLoopCore / PumpMfcThreadMessage`
- On failure path, dispatcher calls:
  - `ShutdownImperialismApplicationInstance (vtable +0x70)`.
- First app-posted startup command is code-confirmed as:
  - `InitializeImperialismApplicationInstance`
  - `-> PostMessageA(mainWnd, WM_COMMAND, 100, 0)`
  - `-> TMacViewMgr message-map entry @ 0x006487c8`
  - `-> HandleStartupCommand100`
  - `-> AdvanceGlobalTurnStateMachine`.
- Current early state-seed hypothesis (code-backed):
  - `g_pLocalizationTable`-backed state object starts at state `1`
  - first startup dispatch advances `1 -> 3 -> 2 -> 0x10` across initial ticks.
- `WM_COMMAND 100` is now confirmed as a reusable scheduler trigger:
  - initially posted from startup init (`0x00412dc0`)
  - later re-posted from dialog accept path (`0x00413f60`).
- `WM_COMMAND 100` currently has two static message-map entry points converging to the same handler:
  - TMacViewMgr map entry `0x006487c8` -> `0x0040132a`
  - app singleton map entry `0x0063e1f0` -> `0x00407c48`
  - both route to `HandleStartupCommand100 @ 0x00413950`.
- Frame/runtime-class mapping for startup doc template is now code-confirmed:
  - document class: `CAmbitDocument`
  - frame class: `TMacViewMgr`
  - view class: `CIncludeView`.
- Startup tail event-dispatch model is now mapped end-to-end:
  - `AdvanceGlobalTurnStateMachine` emits direct event constants and async `0x2420` posts.
  - `HandleCustomMessage2420DispatchTurnEvent` forwards `wParam` into `DispatchGlobalTurnEventCode`.
  - Dispatcher default path enters callback-factory dispatch (`DispatchTurnEventPacketThroughDialogFactory` -> `InvokeDialogFactoryFromPacket` -> `RunRegisteredDialogFactoriesByEventCode`); `0x1036/0x104F/0x10CC` are code-confirmed in `BuildTurnEventDialogUiByCode`.

## Remaining Tasks
1. Identify concrete runtime/data seed path(s) that can introduce event code `0x3B6` into dispatcher input (e.g., network/external payload, scripted/runtime table feed, or UI data-driven list population), since static in-module producers and save/load restoration are now exhausted.

## Risks / Unknowns
- Some lifecycle calls are virtual/indirect, so direct xref call edges are incomplete.
