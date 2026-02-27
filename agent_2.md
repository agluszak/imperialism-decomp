# Agent 2 Minimal Notes

## 2026-02-22 Batch452
- Turn-instruction lane refreshed:
  - Re-ran `create_turn_instruction_types.py`.
  - Extended bindings for `pric/prov/tbar/tclr/coun`.
  - Re-applied `apply_turn_instruction_struct_signatures.py` on extended bindings (`planned=26`, `sig_ok=26`).
- UMapper core lane refreshed in sequential writer mode:
  - `create_umapper_overlay_types.py`
  - `create_umapper_array_state_structs.py`
  - `create_city_region_remap_types.py`
  - Verified unresolved/cluster names in `0x00528000..0x0052ffff` = `0`.
- Descriptor-vtable closure attempt:
  - Added reusable script: `new_scripts/extract_vtbl_labels_from_class_methods.py`.
  - Applied 2 canonical vtable labels:
    - `g_vtblTIndexAndRankList` @ `0x00672eac`
    - `g_vtblTTooltipRelayWindowState` @ `0x006744fc`
  - Post inventory: `vtbl_count=226`, `classes_missing_vtbl=229`, `T desc+no-vtbl=182`.
- Signature hygiene check:
  - `apply_class_helper_signatures.py --apply` produced `ok=0`, `skip=651` (already normalized).

## Current Blocker
- Large `T* class_desc` set still lacks canonical `g_vtblT*` labels, but most such classes show no recoverable vtable-store evidence in their attached methods. Need alternate evidence source (constructor anchor expansion or safe shared-vtable alias policy by explicit provenance).

## 2026-02-22 Batch452 (follow-up)
- Added reusable scripts:
  - `new_scripts/create_control_tag_enum.py`
  - `new_scripts/annotate_control_tag_constants.py`
  - `new_scripts/extract_vtbl_labels_from_class_methods.py`
- Control-tag dehardcode progress:
  - Created `/imperialism/EControlTagFourCC` (27 entries, includes `txen/yako/enod`).
  - Added 29 EOL enum annotations in command-tag handlers (including tactical + trade + dialog paths).
- Class/vtable closure progress:
  - Method-evidence script recovered canonical labels:
    - `g_vtblTIndexAndRankList` (`0x00672eac`)
    - `g_vtblTTooltipRelayWindowState` (`0x006744fc`)
- Invariants snapshot:
  - strict super-lane rows = `0`
  - runtime bridge rows = `0`
  - unresolved rows = `88`
- Startup/runtime check:
  - Added reusable tracer `new_scripts/trace_startup_winapi_chain.py`.
  - Trace shows startup/message pump chain already named; unresolved rename candidates = `0`.

## 2026-02-22 Batch453
- Added reusable script:
  - `new_scripts/apply_control_tag_enum_param_types.py`
- Control-tag typing pass:
  - Generated fresh command-tag matrix (`batch453_command_tag_dispatch_matrix.csv`).
  - Applied `EControlTagFourCC` to high-confidence handler params.
  - Signature scan now shows 10 typed functions (5 core + 5 forwarding thunks), including:
    - `HandleNationStatusDialogCommand`
    - `HandleTacticalBattleCommandTag`
    - `ApplyCityViewBuildingOrderDialogResult`
    - `ApplyCityProductionDialogChanges`
    - `DestructTRailheadDialogAndMaybeFree`
- Neo4j control-tag canonicalization:
  - Canonical nodes confirmed/updated:
    - `control_tag:next` (`txen`)
    - `control_tag:done` (`enod`)
  - `okay` and raw `yako` are now intentionally separate:
    - `control_tag:okay` is semantic-only (no raw `tag_le`)
    - `control_tag:yako` carries raw usage edges (`OBSERVED_IN` / `HANDLED_BY`)
  - Consolidated duplicate `done` tag nodes and migrated relationships.
- Descriptor/vtable lane attempt:
  - Re-ran ctor-neighbor / named-ctor / class-method vtbl recovery scripts.
  - No additional safe canonical `g_vtblT*` labels recovered in this pass.
- Domain-constant refresh:
  - Re-applied gameplay enum/tables in clean sequential writer mode:
    - `create_gameplay_enums.py --apply-tactical-tables`
    - `create_arrow_command_enum.py`
    - `create_control_tag_enum.py`
  - Rechecked arrow-constant comment pass (`annotate_arrow_command_constants.py`) -> no new annotations needed.

## 2026-02-22 Batch454 (control-tag identity correction)
- Corrected raw-vs-semantic control-tag modeling per user guidance:
  - Raw usage tags now separated from semantic labels for all three:
    - raw: `control_tag:txen`, `control_tag:enod`, `control_tag:yako`
    - semantic-only: `control_tag:next`, `control_tag:done`, `control_tag:okay`
  - Migrated `HANDLED_BY` / `OBSERVED_IN` edges from semantic nodes to raw nodes.
  - Removed `RELATES_TO` links to avoid implying equivalence of purpose.
- Updated Ghidra control-tag enum/comment tooling to use raw identifiers only:
  - `EControlTagFourCC` members now `CONTROL_TAG_<TAG>` (e.g. `CONTROL_TAG_TXEN`).
  - Re-applied command-tag constant annotations with raw member names.

## 2026-02-22 Batch456
- Added reusable script:
  - `new_scripts/create_map_interaction_mode_enum_and_apply.py`
- Domain constant dehardcoding progress:
  - Created `/imperialism/EMapInteractionMode` from observed `SetMapInteractionMode` callsites (`0..5`).
  - Typed `SetMapInteractionMode` mode parameter with `EMapInteractionMode` (core/thunk path).
  - Added 23 EOL annotations at mode callsites (`MAP_INTERACTION_MODE_<n>`).
- TODO reprioritized for higher ROI:
  - Active lanes now: domain constants completion, diplomacy semantics, trade residual IDs.
  - Descriptor/vtable closure moved to backlog with explicit blocker note.

## 2026-02-22 Batch456 (diplomacy raw-code pass)
- Added reusable script:
  - `new_scripts/create_diplomacy_raw_enums_and_annotate.py`
- Created and applied raw diplomacy enums:
  - `/imperialism/EDiplomacyRelationCodeRaw` values `2..6`
  - `/imperialism/EDiplomacyActionCodeRaw` values `0,1,10,13,60`
- Added focused CMP/PUSH annotations in high-traffic diplomacy handlers:
  - `ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode`
  - `ValidateDiplomacyProposalTargetAndShowBlockedDetails`
  - `RunDiplomacyNegotiationPopupAndAwaitResponse`
  - `RunDiplomacyWaitSheetPopupAndAwaitResponse`
  - `HandleDiplomacyTurnEventPacketByCode`
  - `BuildNationActionOptionCardsFromRelationTable`
  - `RefreshNationStatusDialogRowsAndSummaryMessage`
  - `RenderMapDialogDiplomacyNeighborRelationHints`
  - total annotations set: `74`
- Added reusable analysis script:
  - `new_scripts/generate_diplomacy_code_matrix.py`
- Exported raw diplomacy constant matrix:
  - `tmp_decomp/batch456_diplomacy_code_matrix.csv`
  - rows: `690` (CMP/PUSH hits for raw relation/action candidate values)
- Added compact hotspot summary:
  - `tmp_decomp/batch456_diplomacy_code_matrix_summary.txt`
  - high-yield next functions for 13/10/5 mapping:
    - `BuildNationActionOptionCardsFromRelationTable`
    - `ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode`
    - `ResolveDiplomacyActionFromClickAndUpdateTarget`
    - `ProcessDiplomacyTurnStateEventStateMachine`
    - `HandleNationStatusDialogCommand`

## 2026-02-22 Batch457
- Added reusable script:
  - `new_scripts/apply_diplomacy_relation_param_types.py`
- Applied `EDiplomacyRelationCodeRaw` to relation-code params in core + thunk helpers:
  - `SetNationPairDiplomacyRelationWithFinalFlag`
  - `SetNationPairDiplomacyRelationAndApplySideEffects`
  - and their thunk mirrors
  - signature updates: `ok=2, skip=2, fail=0` (all 4 now typed)
- Added reusable script:
  - `new_scripts/annotate_diplomacy_hotspot_plate_comments.py`
- Added plate comments (raw evidence, non-semantic) to diplomacy hotspots:
  - `ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode`
  - `ResolveDiplomacyActionFromClickAndUpdateTarget`
  - `BuildNationActionOptionCardsFromRelationTable`
  - `ProcessDiplomacyTurnStateEventStateMachine`
  - `HandleNationStatusDialogCommand`

## 2026-02-22 Batch462
- Added reusable script:
  - `new_scripts/create_diplomacy_proposal_enum_and_apply.py`
- Created and applied new raw proposal enum:
  - `/imperialism/EDiplomacyProposalCodeRaw` (`0x02..0x0F`)
- Signature/type upgrades in diplomacy action flow:
  - `ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode` + thunk:
    - typed as `__thiscall (..., short sourceNationSlot, short targetNationSlot, EDiplomacyProposalCodeRaw eProposalCode)`
  - `ResolveDiplomacyActionFromClickAndUpdateTarget` + thunk:
    - typed as `__thiscall (..., pCursorPoint) -> EDiplomacyProposalCodeRaw`
  - `HandleDiplomacySelectedNationActionCommand` + thunk:
    - typed as `__thiscall (..., pCursorPoint)`
- Trade residual ID follow-up:
  - re-ran selection-path trace confirms `2115/2117/2119` absent in trade bitmap flow;
    `2116` remains struct-offset constant domain.

## 2026-02-22 Batch463
- Domain-constant follow-up:
  - Re-ran turn-event typing scripts in sequential writer mode:
    - `create_turn_event_factory_slot_enum.py`
    - `create_turn_event_factory_packet_struct_and_apply.py`
  - `ETurnEventFactorySlotId` remained stable (`15` entries), packet signatures remained aligned.
- Added reusable scripts:
  - `new_scripts/apply_diplomacy_action_cards_signature.py`
  - `new_scripts/rename_diplomacy_runtime_value_tables.py`
- Applied diplomacy signature/label updates:
  - `BuildNationActionOptionCardsFromRelationTable` + thunk retyped to:
    - `__thiscall (this, short sourceNationSlot, int* pRowCursor, int* pColumnCursor)`
  - Renamed runtime value table symbol:
    - `0x0069695c` -> `g_awDiplomacyTradePolicyIconValueTable`
  - Reaffirmed/annotated:
    - `0x00696948` `g_awDiplomacyGrantAndTradePolicyValueTable`

## 2026-02-22 Batch466
- Switched this pass to CSV-driven batch application for globals (per speed-up policy):
  - Added reusable script: `new_scripts/apply_global_data_from_csv.py`
  - Applied batch file: `tmp_decomp/batch466_global_data_apply.csv`
- Data dehardcode lane (high-xref globals) progress:
  - Created and applied `/imperialism/runtime/TUiResourcePoolState` at `0x006a13e0`.
  - Renamed/annotated pool fields:
    - `g_pUiResourcePoolChainHead` (`0x006a13e4`)
    - `g_pUiResourcePoolChainTop` (`0x006a13e8`)
    - `g_nUiResourcePoolDepth` (`0x006a13ec`)
    - `g_pUiResourcePoolFreeListHead` (`0x006a13f0`)
    - `g_pUiResourcePoolBlockChainHead` (`0x006a13f4`)
    - `g_nUiResourcePoolNodesPerBlock` (`0x006a13f8`)
  - Renamed/typed runtime globals:
    - `g_szEmptyString` (`0x006a13a0`, byte)
    - `g_pDisplayManager` (`0x006a2158`, void*)
    - `g_pActiveQuickDrawSurfaceContext` (`0x006a1d60`, void*)
    - `g_pCurrentQuickDrawSurfaceContext` (`0x006950f8`, void*)
    - `g_DefaultQuickDrawSurfaceContext` (`0x006a1ca0`, void*)
    - `g_pQuickDrawActiveMemoryDc` (`0x006a1da0`, void*)
    - `g_nQuickDrawContextFlags` (`0x006a1db0`, int)
    - `g_hQuickDrawPreviousSelectedObject` (`0x006a1dbc`, void*)
- Verification snapshot:
  - `SetActiveQuickDrawSurfaceContext` and `LoadBitmapResourceSurfaceAndRestoreQuickDrawContext` now decompile with typed quickdraw/display globals instead of `DAT_*`/`PTR_DAT_*`.
  - `RegisterUiResourceEntry`/`PopUiResourcePoolNode` now decompile against `g_UiResourcePoolState` fields.

## 2026-02-22 Batch467
- Continued CSV-wave dehardcoding using `new_scripts/apply_global_data_from_csv.py`.
- Window registry globals dehardcoded (used by `TWindow`/`TFloatWindow` create/destroy):
  - `g_pWindowRegistryHead` (`0x006a1a44`)
  - `g_pWindowRegistryTail` (`0x006a1a48`)
  - `g_nWindowRegistryCount` (`0x006a1a4c`)
  - `g_pWindowRegistryFreeListHead` (`0x006a1a50`)
  - `g_pWindowRegistryBlockChainHead` (`0x006a1a54`)
  - `g_nWindowRegistryNodesPerBlock` (`0x006a1a58`)
- Runtime selection record buffer globals dehardcoded:
  - `g_RuntimeSelectionRecordArrayState` (`0x006a15e0`)
  - `g_pRuntimeSelectionRecordArray` (`0x006a15e4`)
  - `g_nRuntimeSelectionRecordCount` (`0x006a15e8`)
  - `g_nRuntimeSelectionRecordCapacity` (`0x006a15ec`)
  - `g_nRuntimeSelectionRecordGrowthStep` (`0x006a15f0`)
- Scoped map quickdraw globals and helper function names normalized:
  - globals:
    - `g_pScopedMapQuickDrawDcHandleObject` (`0x006a1d9c`)

## 2026-02-22 Batch588..593 (Decomp quality closure waves)
- Added reusable scripts:
  - `new_scripts/apply_hidden_param_signature_wave.py`
  - `new_scripts/apply_hidden_ecx_fastcall_wave.py`
- Signature artifact burn-down (CSV-driven, single-writer waves):
  - `batch588`: global stack-arg contiguous wave (`ok=14`, `skip=11`, `fail=0`)
  - `batch589`: extended global stack-arg contiguous wave (`ok=8`, `skip=8`, `fail=0`)
  - `batch590`: broad class hidden-this wave via `fix_hidden_this_in_class_methods.py --class-regex '^T'` (`ok=343`, `skip=75`, `fail=0`)
  - `batch591`: strict paired thunk/core fastcall wave (`ok=7`, `skip=7`, `fail=0`)
  - `batch593`: active gameplay class stack-param wave (`ok=3`, `skip=0`, `fail=0`)
- Hidden artifact metric deltas:
  - from `batch585`: `in_ECX_total=1780`, `in_stack_arg_total=1719`, `rows=409`
  - to `batch593`: `in_ECX_total=1278`, `in_stack_arg_total=1451`, `rows=346`
  - net: `in_ECX -502`, `in_stack_arg -268`, `rows -63`
    - `g_pScopedMapQuickDrawViewContext` (`0x006a1dac`)
  - functions:
    - `BindScopedMapQuickDrawDcHandle` (`0x004945f0`)
    - `ReleaseScopedMapQuickDrawDcHandle` (`0x004946b0`)

## 2026-02-22 Batch468
- Startup/runtime singleton globals dehardcoded:
  - `g_pGlobalUiRootController` (`0x006a1344`)
  - `g_pModuleLibraryCacheState` (`0x006a134c`)
- Multiplayer turn-event queue singleton dehardcoded:
  - `g_pGlobalTurnEventQueueManager` (`0x006a6014`)
- Verification:
  - `InitializeImperialismApplicationInstance` / `ShutdownImperialismApplicationInstance`
    now use named startup singletons instead of `DAT_*`.
  - `InitializeMultiplayerManagerForSessionContext` / `ShutdownRuntimeSelectionAndPersistPlayerName`
    now use named global turn-event queue manager.

## 2026-02-22 Batch470
- CSV-wave speedup tooling:
  - Extended `new_scripts/apply_global_data_from_csv.py` to accept array types in CSV (e.g. `void*[23]`, `uint[16]`) and added `dword` alias support.
- Applied one runtime-state dehardcode batch via CSV:
  - input: `tmp_decomp/batch470_runtime_state_globals_apply.csv`
  - apply log: `tmp_decomp/batch470_runtime_state_globals_apply.log`
- Dehardcoded/typed globals in one transaction:
  - `0x006a429c` -> `g_apNationAuxRuntimeStateSlots` (`void*[16]`)
  - `0x006a4310` -> `g_apTerrainTypeDescriptorTable` (`void*[23]`)
  - `0x006a4370` -> `g_apNationStates` (`void*[7]`)
  - `0x006a43c0` -> `g_bTurnFlowReinitPending` (`byte`)
  - `0x006a43c4` -> `g_wTurnFlowCooldownCounter` (`ushort`)
  - `0x006a43f0` -> `g_bScenarioSetupModeActive` (`byte`)
  - `0x006a43f4` -> `g_bAccumulateNavyOrderResourceDeltasEnabled` (`byte`)
- Verification snapshot (`tmp_decomp/batch470_verify_context.txt`):
  - `DestroyGlobalOrderManagersAndState` now decompiles with explicit typed array loops (`g_apTerrainTypeDescriptorTable`, `g_apNationStates`, `g_apNationAuxRuntimeStateSlots`) instead of `DAT_*` pointer arithmetic.
  - `RebuildNationStateSlotsAndAvailability`, `RebuildMapContextAndGlobalMapState`, and `AdvanceGlobalTurnStateMachine` now use named setup/turn-flow flags (`g_bScenarioSetupModeActive`, `g_bTurnFlowReinitPending`, `g_wTurnFlowCooldownCounter`).
  - `AccumulateRandomizedNavyOrderResourceDeltasByNationAndOwner` now reads named debug/override flag (`g_bAccumulateNavyOrderResourceDeltasEnabled`).

## 2026-02-22 Batch471
- Continued CSV-wave dehardcoding (`new_scripts/apply_global_data_from_csv.py`):
  - input: `tmp_decomp/batch471_datetime_quickdraw_globals_apply.csv`
  - apply log: `tmp_decomp/batch471_datetime_quickdraw_globals_apply.log`
- Renamed/typed globals:
  - `0x006a815c` -> `g_bDateTimeDirectiveAlternateWidthRequested` (`int`)
  - `0x006a8160` -> `g_bDateTimeNumericVariableWidthMode` (`int`)
  - `0x006a1d48` -> `g_hQuickDrawCachedFontHandle` (`void*`)
  - `0x006a1d56` -> `g_bQuickDrawStyleDirty` (`byte`)
- Verification (`tmp_decomp/batch471_verify_context.txt`):
  - Date/time format lane now decompiles with explicit width-policy globals in:
    - `FormatBufferWithPercentDirectivesAndLocaleLock`
    - `ExpandDateTimeFormatDirectiveToBuffer`
    - `WriteIntegerDigitsToOutputWithWidthPolicy`
  - QuickDraw text lane now decompiles with explicit cached-style globals in:
    - `DrawTextWithCachedQuickDrawStyleState`
    - `MeasureTextExtentWithCachedQuickDrawStyle`

## 2026-02-22 - DAT Dehardcode Large Waves (batch476-479)
- Applied `batch476_dat_dehardcode_apply.csv` (10 globals): setup token/app root, join-game descriptor core, map-action distance/cache count, CRT low-IO slot capacity, audio mode, backdrop state.
- Applied `batch477_join_runtime_globals_apply.csv` (18 globals): runtime selection source arrays/counters, deferred turn-event queue heads/tails/count/free-list/block-chain, runtime network status/session path tokens.
- Applied `batch478_map_order_globals_apply.csv` (8 globals): navy list heads, resolved tile action context, active map-order context, map-action list head, capability averages array.
- Applied `batch479_runtime_queue_manager_fix.csv` (1 global): corrected `0x006a5f64` to `g_pRuntimeTurnEventQueueManager` (`void*`).
- Verification artifacts: `tmp_decomp/batch476_verify_context.txt`, `tmp_decomp/batch477_verify_context.txt`, `tmp_decomp/batch478_479_verify_context.txt`.
- Applied `batch480_crt_runtime_globals_apply.csv` (4 globals): CRT process heap handle, CRT exit-handler vector base/next pointers, process command-line pointer.
- Fresh counters after batch480:
  - `tmp_decomp/progress_count_re_progress_latest.txt`: `total_functions=13829`, `renamed_functions=13829`, `default_fun_or_thunk_fun=0`, `class_desc_count=406`, `vtbl_count=233`.
  - `tmp_decomp/progress_dat_with_refs_latest.txt`: `dat_with_refs=6284`.

## 2026-02-22 Batch484-485
- Continued CSV-driven DAT dehardcode in two larger waves:
  - `tmp_decomp/batch484_constructor_defaults_apply.csv` (22 globals)
  - `tmp_decomp/batch485_quickdraw_globals_apply.csv` (12 globals)
- Key lanes covered:
  - save/setup defaults: `g_szSaveSlotDisplayLabel`, setup palette origins, UI resource default params
  - mouse capture state: owner pointer, anchor/prev/current XY coordinates, repeat timer id
  - font preset cache: preset tuple words + dirty flag + cached font object
  - quickdraw lane: text/global origins, stroke style pair, font style word, current color, clip-handle map pointer, reusable surface list head
- Verification contexts:
  - `tmp_decomp/batch484_verify_context.txt`
  - `tmp_decomp/batch485_verify_context.txt`
- Added reusable stats helper:
  - `new_scripts/count_dat_with_refs.py`
- Fresh counters after batch485:
  - `tmp_decomp/progress_count_re_progress_latest.txt`: `total_functions=13829`, `renamed_functions=13829`, `default_fun_or_thunk_fun=0`, `class_desc_count=406`, `vtbl_count=233`.
  - `tmp_decomp/progress_dat_with_refs_latest.txt`: `dat_with_refs=6204`.

## 2026-02-22 Batch486
- Applied `tmp_decomp/batch486_modal_state_globals_apply.csv` (7 globals) for modal push/pop chain state:
  - `g_pViewModalStateNodeBlockChainHead`
  - `g_pViewModalStateNodeChainHead`
  - `g_pViewModalStateNodeChainTail`
  - `g_nViewModalStateDepth`
  - `g_pViewModalStateNodeFreeList`
  - `g_pViewModalStateNodePoolBlockChainHead`
  - `g_nViewModalStateNodesPerBlock`
- Verification: `tmp_decomp/batch486_verify_context.txt` (`ExecuteViewModalStateWithPushPopChain` now decompiles with explicit modal-node globals).
- Counter: `dat_with_refs=6197`.

## 2026-02-22 Batch487
- Applied `tmp_decomp/batch487_runtime_env_globals_apply.csv` (8 globals) for CRT env/argv lane:
  - `g_pszEnvironmentBlockAnsi`
  - `g_ppszEnvironmentEntriesAnsi`
  - `g_ppszEnvironmentEntriesAnsiBaseline`
  - `g_ppwcsEnvironmentEntriesWide`
  - `g_nArgvUpperBound`
  - `g_ppszArgv`
  - `g_pszArgvProgramPath`
  - `g_szModulePathBuffer`
- Verification: `tmp_decomp/batch487_verify_context.txt` (entry, env sync, argv parse all show named globals).
- Counter: `dat_with_refs=6189`.

## 2026-02-22 Batch488
- Applied `tmp_decomp/batch488_mfc_doc_template_globals_apply.csv` (3 globals) for MFC pending doc-template lane:
  - `g_pPendingDocTemplateManager`
  - `g_pPendingDocTemplateListHead`
  - `g_szMfcScratchBuffer`
- Verification: `tmp_decomp/batch488_verify_context.txt` (doc-template constructor/flush/init paths now decompile with named globals).
- Counter: `dat_with_refs=6186`.

## 2026-02-22 Batch490
- Added reusable/global CSV wave and applied (`ok=11`) for high-xref data dehardcoding:
  - buffered stream lane:
    - `0x006a8478` -> `g_apBufferedStreamSlots` (`void**`)
    - `0x006a97c0` -> `g_nBufferedStreamSlotCount` (`int`)
  - panel/overlay lane:
    - `0x006a4194` -> `g_pPanelBitmapBlitSurfaceState` (`void*`)
    - `0x006a4450/4454` -> `g_nOverlayClipCacheParamX/Y` (`int`)
  - shared message/string refs:
    - `0x006a1f80` -> `g_ShListBoxDelimitedTailRef`
    - `0x006a3180` -> `g_ShTurnAdvisoryMessageRef`
    - `0x006a2df0` -> `g_ShGreatPowerPressureMessageRef`
    - `0x006a5a00/5a28` -> `g_ShTradeSelectionPrimary/SecondaryLabelRef`
  - flavor text rotation counters:
    - `0x006a5af0` -> `g_awFlavorTextRotationCounterBySlot` (`ushort[23]`)
- Verification:
  - decomp now uses renamed symbols in stream acquire/flush and flavor-text rotation helpers.

## 2026-02-22 Batch491
- Applied message-ref dehardcode wave (`ok=10`) + top-level temp map handle:
  - `0x006a2d40` -> `g_ShCivilianOrderDialogMessageRef`
  - `0x006a2fc0` -> `g_ShDiplomacyActionRejectMessageRef`
  - `0x006a3020` -> `g_ShDiplomacyNegotiationDialogMessageRef`
  - `0x006a3d08` -> `g_ShNationStatusAwolMessageRef`
  - `0x006a45c0` -> `g_ShTurnSummaryDialogMessageRef`
  - `0x006a4048` -> `g_ShInterNationSummaryDialogMessageRef`
  - `0x006a5ed8` -> `g_ShNetworkWarningDialogMessageRef`
  - `0x006a5be0` -> `g_ShLocalizedPromptDialogMessageRef`
  - `0x006a2288` -> `g_ShOrderPlacementWarningMessageRef`
  - `0x006a2054` -> `g_pTopLevelWindowTempMapHandle` (`void*`)
- Verification:
  - atlas and decomp contexts reflect new names across diplomacy/turn/network/order warning paths.

## 2026-02-22 Batch492
- Applied map-interaction preview lane:
  - globals (`ok=4`):
    - `0x006a33b0` -> `g_wMapDialogTileRowMarker` (`short`)
    - `0x006a33b4` -> `g_nMapInteractionPreviewParityX` (`int`)
    - `0x006a33b8` -> `g_nMapInteractionPreviewParityY` (`int`)
    - `0x006a3370` -> `g_ShHomeSelectionPortBuildDialogMessageRef` (`int`)
  - function rename:
    - `0x0051af60` -> `UpdateMapInteractionPreviewParityAndRenderTransientSprites`
  - signature:
    - `0x0051af60` -> `void __thiscall (..., void* pThis)`
- Verification:
  - decomp now references map preview parity globals and renamed function in render/update path.

## Snapshot
- `dat_with_refs`: `6160`

## 2026-02-22 Batch493
- Applied runtime signal/locale fallback dehardcode wave (`ok=5`):
  - `0x006a843c` -> `g_pRuntimeSignalHandlerCode02` (`void*`)
  - `0x006a8448` -> `g_pRuntimeSignalHandlerCode0F` (`void*`)
  - `0x006a844c` -> `g_bRuntimeConsoleCtrlHandlerInstalled` (`int`)
  - `0x006a8470` -> `g_nLocaleCompareStringApiMode` (`int`)
  - `0x006a60c0` -> `g_RuntimeLocalizationAudioSlotState` (`int`)
- Verification:
  - decomp now shows handler-slot globals in `SetCrtSignalHandlerWithConsoleCtrlSetup` and `RaiseRuntimeSignalAndInvokeHandler`.
  - locale compare routine now uses `g_nLocaleCompareStringApiMode` instead of `DAT_006a8470`.

## Snapshot
- `dat_with_refs`: `6155`

## 2026-02-22 Batch494
- Applied city/civilian legend state bridge wave (`ok=3`):
  - `0x006a4490` -> `g_awCivilianLegendSelectionCountsBySlot` (`ushort[16]`)
  - `0x006a44b0` -> `g_pActiveCityDialogLegendSelectionOwner` (`void*`)
  - `0x006a44b4` -> `g_bCityDialogLegendSelectionInitialized` (`int`)
- Verification:
  - city dialog selection/reset path and civilian legend refresh now use typed globals instead of `DAT_*` symbols.

## 2026-02-22 Batch495
- Applied navy priority table wave (`ok=3`):
  - `0x006a3e28` -> `g_awNavyOrderPriorityPermutationByMetricA` (`ushort[14]`)
  - `0x006a3e50` -> `g_awNavyOrderPriorityPermutationByMetricB` (`ushort[14]`)
  - `0x006a3e90` -> `g_awNavyOrderPriorityPermutationByMetricC` (`ushort[14]`)
- Verification:
  - `InitializeNavyOrderPriorityTables` now decompiles against explicit typed permutation arrays.

## Snapshot
- `dat_with_refs`: `6141`

## 2026-02-22 Batch496
- Applied allocator/tactical/message-dispatch cache wave (`ok=5`):
  - `0x006a81c8` -> `g_nAllocatorFreePageCandidateCount` (`int`)
  - `0x006a475c` -> `g_pActiveTacticalBattleStateBuffer` (`void*`)
  - `0x006a6150` -> `g_adwAfxMsgMapDispatchCacheKey` (`uint`)
  - `0x006a6154` -> `g_apAfxMsgMapDispatchCacheEntry` (`void*`)
  - `0x006a6158` -> `g_apAfxMsgMapDispatchCacheClassMap` (`void*`)
- Verification:
  - allocator free/release routines now use `g_nAllocatorFreePageCandidateCount`.
  - message dispatch decomp now shows 3-field cache arrays (`key/entry/class`) with `[uVar5 * 3]` indexing.

## Snapshot
- `dat_with_refs`: `6136`

## 2026-02-22 Batch497
- Applied mini-map/turn-event defaults wave (`ok=3`):
  - `0x006a460c` -> `g_wMiniMapViewHalfWidth` (`short`)
  - `0x006a5b58` -> `g_dwTurnEventDispatchStateDefaultA` (`int`)
  - `0x006a5b5c` -> `g_dwTurnEventDispatchStateDefaultB` (`int`)
- Verification:
  - mini-map constructors and overlay-mode entry now use `g_wMiniMapViewHalfWidth`.
  - `ConstructGlobalTurnEventState` and `DeserializeTurnEventDispatchState` now use the renamed default state pair.

## Snapshot
- `dat_with_refs`: `6133`

## 2026-02-22 Batch499
- Applied `tmp_decomp/batch499_global_data_apply.csv` (`ok=37`) in one writer pass.
- Major dehardcode lanes:
  - nation order-priority metric arrays (`0x006a3a88/3ac0/3ae0/3b20/3b50/3b88`) typed as `float[7]`
  - turn/map state gates (`g_bTurnInstructionAbortRequested`, `g_nTurnInstructionTokenDispatchCount`, map-action blink globals)
  - timer slot runtime tables (`g_adwTimerSlotWin32IdByIndex`, `g_apfnTimerSlotCallbackByIndex`)
  - runtime locale/timezone capability caches and lazy user32 proc pointers (`0x006a81cc..0x006a8458` subset)
  - singleton/factory/clip anchors (`g_ImperialismAppSingletonGlobal`, `g_adwTurnEventFactoryDispatchScratch`, `g_pGlobalClipRegionHandleObject`)
- Verification artifacts:
  - `tmp_decomp/batch499_verify_metrics_ctx.txt`
  - `tmp_decomp/batch499_verify_turn_timer_ctx.txt`
  - `tmp_decomp/batch499_verify_runtime_ctx.txt`
- Snapshot:
  - `dat_with_refs`: `6088`
  - `total_functions`: `13829`, `default_fun_or_thunk_fun`: `0`

## 2026-02-22 Batch500
- Applied `tmp_decomp/batch500_global_data_apply.csv` (`ok=7`) to close all unresolved `DAT_*` entries with `code_refs >= 3`.
- Added/typed:
  - `g_bGameplayHintBlinkPhaseToggle`
  - `g_aTacticalUnitFacingOffsetPairs`, `g_aTacticalUnitFacingOffsetPairsYLane`
  - `g_ShLoadGlobalSystemsStatusMessageRef`
  - `g_ShDiplomacyWaitSheetMessageRef`
  - `g_dwScrollInfoApiGateVersion`
  - `g_nRuntimeErrorOutputModeGate`
- Snapshot:
  - unresolved `DAT_*` with `code_refs >= 3`: `0`
  - `dat_with_refs`: `6081`

## 2026-02-22 Batch501/502
- Continued `batch501_global_data_wave_active.csv` in two large passes and re-applied in one writer each.
- Added high-confidence globals for:
  - message fallback/init guards, city-building action-rect coordinates, backdrop window gate
  - static dialog-template storage, ocean dialog default origins, tactical intro gate
  - MFC create-window default rect, runtime selection storage anchors
  - runtime DST/timezone rule fields and optional C++ exception validation hook
  - MFC exception anchor pointers (`$E350/$E355/$E361/$E377` call paths)
- Post-wave results:
  - `tmp_decomp/batch502i_dat_atlas_min2_post.csv`: `rows=0` (`DAT_006a*` with `code_refs>=2` fully cleared)
  - `tmp_decomp/progress_dat_with_refs_latest.txt`: `dat_with_refs 6007`

## 2026-02-22 Batch503
- Executable coverage sweep:
  - `new_scripts/functionize_missing_branch_targets.py` still reports one candidate (`0x00552342`) but apply pass shows `created=0 skipped=1` (tail-jump boundary; no safe function start).
- Signature hygiene pass (`tmp_decomp/batch503_signature_wave.csv`):
  - applied `ok=9 skip=1 fail=0`
  - stabilized prototypes/returns for:
    - `AppendStatusPointerAndDispatchMessageFallback`
    - `InitializeGlobalPair6A1FC0And6A1FC4Default`
    - `UpdateGlobalWord6A2008FromScaled6A1FC0`
    - `SetGlobalDword6A2018`
    - `WrapperFor_AllocateWithFallbackHandler_At0049cc60`
    - `CreateRuntimeSelectionRecordEntryIfTagNotReserved`
    - `OpenJoinGameRuntimeSelectionAndStartSession`
    - `InitializeStaticDialogTemplateD0AndRegisterAtExit`
    - `CleanupStaticDialogTemplateD0AtExit`

## 2026-02-22 - Batch534..549 Pre-ReDecomp Checklist Pass
- TODO rewritten to strict pre-redecomp lanes/gates (coverage, ABI, semantics).
- Lane A: branch-target functionize closure verified: only known non-creatable 0x00552342 remains (batch535).
- Lane A: orphan triage refreshed (batch546): 5923 zero-xref entries, dominated by thunk/stub island; actionable closure now documentation/classification rather than function creation.
- Lane B: wrapper-name normalization waves applied: batch538 (30), batch539 (12).
- Lane B: ABI signature waves applied: batch540 (ret0x14: 3), batch547 (ret0x8: 80+9 safe earlier), batch548 (ret0x10: 35).
- Lane B: thunk signature propagation check run (batch541), no remaining simple-callee candidates.
- Lane C: turn-instruction typing/signature lane reapplied and persisted (batch543): 21 handler signatures + typed token/handler tables.
- Lane C: mapgen + UMapper overlay struct scripts rerun (batch544), typed globals confirmed.

## 2026-02-22 - Batch556..572 TODO Loop Pass
- Added reusable script: new_scripts/fix_hidden_this_in_class_methods.py (detect/apply class-method hidden-this fixes from in_ECX + zero-param signatures).
- Added reusable script: new_scripts/build_orphan_intent_inventory.py (orphan triage enrichment with intent buckets + data-ref evidence).
- Added reusable script: new_scripts/scan_hidden_decomp_params.py (anchor lane hidden-param scanner for in_ECX/in_stack).
- Orphan ownership closure evidence:
  - batch567 inventory: intentional_thunk_entry=3922, data_driven_entrypoint=828, detached_callchain_no_inrefs=818, intentional_stub=216, intentional_wrapper=130, intentional_dead_leaf_named=9.
  - batch566: renamed 9 dead leaves to OrphanDeadLeaf_*.
- ABI/class-signature cleanup:
  - batch563 hidden-this pass applied ok=55 skip=3 fail=0 for map/startup/view-manager class namespaces.
  - batch564 verify: no remaining hidden-this candidates for that class regex.
  - batch569 class-only hidden-param scan: in_ECX_total=0, in_stack_total=259 across 30 methods (residual lane).
- Class/vtable closure checks: pattern/neighbor/vtable extraction scripts mostly saturated (no new candidates); unique-vtable attach remains low-yield.
- Gates: strict super-lane=0 (batch572_strict_gate.csv), runtime unresolved 0x00600000..0x0062ffff=0.

## 2026-02-22 - Batch573..575 Follow-up
- Ran map/startup RET-immediate safe signature probes in TMap*/TViewMgr lanes (ret 0x4/0x8/0xC/0x10): no additional zero-param candidates remained.
- Gameplay enum lane advanced (batch574): refreshed EHexDirection/EHexDirectionMask/ETacticalUnitActionClass/ETacticalUnitCategoryCode and retyped tactical slot tables.
- Hidden-parameter anchor scan (batch568/batch569):
  - broad anchor scan: 424 funcs flagged (mixed global + class lanes).
  - class-only anchor scan after hidden-this fix: in_ECX_total=0, residual in_stack_total=259 across 30 functions.
- Targeted class/vtable closure scripts rerun for anchors (batch570/batch575): no new low-risk attachment/label candidates; lane appears saturated under current conservative rules.

## 2026-02-22 - Batch600..607 Class Attachment Pass
- Re-checked class-quad attachment lane:
  - `apply_class_quads_from_csv` on `batch112_class_quads_merged.csv`: saturated (`fn_ok=0`, `ns_ok=0`).
  - `extract_class_namespaces_from_csv`: saturated (`fn_attached=0`).
  - `attach_unique_vtable_targets_to_class` dry-run: `unique_global_candidates=0`.
  - `attach_class_thunk_targets` dry-run: `unique_targets=0`.
- Added reusable script:
  - `new_scripts/attach_class_methods_by_prefix.py`
  - Purpose: safely attach only `TClass_*` / `thunk_TClass_*` global functions into existing class namespaces.
- Applied strict-prefix class-attachment wave (`batch607`):
  - `ok=29`, `fail=0`
  - moved additional methods into classes, mainly:
    - `TMacViewMgr` command/message handlers
    - `TMapMaker` mapgen helper methods
    - `TArmyTacUnit` slot implementations

## 2026-02-22 - Batch610 Unified Class Attachment Toolkit + Apply
- Added reusable script:
  - `new_scripts/class_attachment_wave_tools.py`
  - Implements six lanes with one interface:
    1) `thiscall-pthis`
    2) `caller-owner`
    3) `thunk-chain`
    4) `inferred-vtbl`
    5) `ui-msg`
    6) `sig-clone`
    - plus `all` runner.
- Ran full apply wave with stricter denylist:
  - command:
    - `.venv/bin/python new_scripts/class_attachment_wave_tools.py all --apply --name-deny-regex '^(thunk_|WrapperFor_|FUN_|Dtor_|Ctor_|`)'`
  - results:
    - `thiscall-pthis`: `ok=44`, `skip_conflict=26`
    - `caller-owner`: `ok=10`
    - `thunk-chain`: `ok=1`
    - `inferred-vtbl`: `ok=3`
    - `ui-msg`: `ok=0`
    - `sig-clone`: `ok=0`
  - total namespace attachments this wave: `58`, `fail=0`.

## 2026-02-22 - Batch617..618 Thunk->Impl Attach From thiscall void* Candidates
- Added reusable scripts:
  - `new_scripts/find_thiscall_voidptr_classpass_candidates.py`
  - `new_scripts/attach_impls_from_thiscall_voidptr_candidates.py`
- Strict candidate sweep confirmed prior observation: most are thunk wrappers.
- Implemented target-resolution flow:
  - resolve thunk/simple-forwarder chain (JMP or CALL;RET), attach terminal implementation to dominant class.
- Applied on strict candidate set:
  - `ns_ok=15`, `ns_fail=0`
  - `type_ok=0` (all skipped for pThis retype gate in this batch)
  - notable lane examples:
    - `FindLinkedListNodeByIdFieldAt18` -> `TMapDialog`
    - `QueueImmediateCivilianCommandAndCycleSelection` -> `TCivToolbar`
    - `ResolveRegionTileSubtypeCodeForTileIndex` -> `TMapMaker`
    - `GetActiveMapOrderEntry` -> `TNavyToolbarCluster`
    - `SelectBestTacticalTileByWeightedHeuristics` -> `TArmyTacUnit`

## 2026-02-22 - Batch620..625 Non-thiscall Caller-Ownership Impl Attach
- Added reusable script:
  - `new_scripts/attach_impls_by_caller_ownership.py`
  - Purpose: attach impl targets by dominant class callers without requiring `__thiscall`.
- Strict apply wave (`min_calls=3`, `min_ratio=0.85`):
  - `target_ok=24`, `target_fail=0`
  - examples:
    - `UpsertPtrListRecordByComparator` -> `THelpMgr`
    - `SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty` -> `TMapDialog`
    - `QueueMapActionMissionFromCandidateAndMarkState` -> `TAutoGreatPower`
    - `SetMapTileStateByteAndNotifyObserver` -> `TZone`
    - `ComputeHexTileDistanceFromIndices` -> `TArmyTacUnit`
- Follow-up relaxed-but-filtered wave (`min_calls=2`, `min_ratio=0.75`, non-wrapper target regex):
  - `target_ok=2`, `target_fail=0`
  - attached:
    - `UIWidget::UpdateSelectionRect` -> `TOfferDeskPicture`
    - `DestroyCClientDCAndReleaseHandle` -> `TMacViewMgr`

## 2026-02-22 - Batch637..652 Decomp-Easing Signature Cleanup Waves
- Goal: reduce hidden decompiler artifacts (`in_ECX`, `in_stack_...`) and redundant `pThis` noise.
- Applied waves:
  - `normalize_thiscall_redundant_pthis.py --apply`
    - pass result: `ok=31 skip=31 fail=0`
    - post-check: `candidates=0`
  - `fix_hidden_this_in_class_methods.py --dry-run --class-regex '^T'`
    - post-check: `candidates=0`
  - `apply_thiscall_stack_params_from_hidden_csv.py` on class sample CSVs:
    - strict wave (`min_stack_hits=8`): `ok=4`
    - follow-up (`min_stack_hits=6`): `ok=7`
    - broad safe wave (`min_stack_hits=4`, `max_params=4`): `ok=16`
    - single-arg lane (`min_stack_hits=2`, `max_params=1`): `ok=28`
    - one high-hit outlier (`min_stack_hits=10`, `max_params=4`): `ok=1`
- Measured impact on class sample scan (`scan_hidden_decomp_params.py --class-regex '^T' --max-functions 2500`):
  - before: `in_stack_arg_total=600`, `rows=110`
  - intermediate: `in_stack_arg_total=255`, `rows=71`
  - after: `in_stack_arg_total=181`, `rows=39`
  - `in_ecx_total` unchanged at `10` (two GreatPower path variants dominate this residual).

## 2026-02-25 - Batch664 Trade-Screen Re-decomp Import (Rename-Only Safe Pass)
- Added reusable helper:
  - `new_scripts/build_redecomp_wave_from_ownership.py`
  - builds wave CSVs from:
    - `/home/agluszak/code/personal/imperialism-decomp/config/function_ownership.csv`
    - `/home/agluszak/code/personal/imperialism-decomp/config/symbols.csv`
  - filtered by owned source lane (used: `src/game/trade_screen.cpp`).
- Important sandbox/runtime note:
  - pyghidra launch in this environment requires:
    - `JAVA_TOOL_OPTIONS='-Duser.home=/tmp'`
    - `HOME=/tmp`
- Applied wave:
  - command lane: `run_wave_bundle.py` with renames CSV only
  - summary:
    - `rename_ok=64`, `rename_skip=19`, `rename_fail=0`
    - `sig_ok=0` (intentionally skipped for safety)
    - strict/runtime gates remained clean:
      - `pre_strict_rows=0`, `post_strict_rows=0`
      - `pre_runtime_rows=0`, `post_runtime_rows=0`
- Safety constraint used:
  - imported only addresses owned by `src/game/trade_screen.cpp` (83 allowlisted addresses),
  - avoided broad signature overwrite to prevent clobbering non-redecomp ABI decisions.

## 2026-02-26 - Batch666 Trade Slot/Bridge Tightening (Ghidra-side)
- Goal: improve decomp readability/match fidelity around trade auto-repeat + split-arrow control flow without touching unrelated functions.
- Added reusable scripts:
  - `new_scripts/apply_thiscall_bridge_signatures_csv.py`
  - `new_scripts/annotate_trade_slot_semantics.py`
- Applied lane 1 (slot typing semantics/comments):
  - created/confirmed enum: `/imperialism/EArrowSplitCommandId`
  - annotated key handlers:
    - `0x00583BD0`, `0x00401B3B`
    - `0x00586E70`, `0x005873E0`, `0x005869C0`
- Applied lane 2 (thiscall bridge normalization, strict address list):
  - CSV: `tmp_decomp/batch666_trade_bridge_signatures.csv`
  - writer result: `ok=8 skip=3 fail=0`
  - key fixes:
    - `0x00586E70` -> `(this, commandId, eventArg, eventExtra)`
    - `0x005873E0` -> `(this, commandId, eventArg, eventExtra)`
    - `0x0059A180` -> `void __thiscall (..., byte enabledFlag)`
    - `0x00587130` -> `void __thiscall (..., uint styleSeed)`
    - tiny wrappers `0x00586A60/80/B0` -> explicit thiscall method shapes
- Applied lane 3 (tiny-wrapper thunk extraction):
  - created named JMP-thunks:
    - `0x004096E2 -> thunk_OrphanTiny_SetWordEcxOffset_8c_00586a60`
    - `0x00402E55 -> thunk_OrphanLeaf_NoCall_Ins05_00586a80`
    - `0x0040324C -> thunk_OrphanTiny_SetWordEcxOffset_8e_00586ab0`
- Post-gates:
  - strict super-lane: `0` rows
  - runtime bridge unresolved (`0x00600000..0x0062ffff`): `0` rows
  - progress snapshot: `total_functions=13832`, `renamed_functions=13832`, `default_fun_or_thunk_fun=0`

## 2026-02-26 Batch680-Batch689 (normalization sprint)
- Trade lane normalization (script-driven waves):
  - Added/fixed reusable scripts:
    - `new_scripts/apply_thiscall_bridge_signatures_csv.py` (targeted ABI patching)
    - `new_scripts/apply_hidden_ecx_fastcall_wave.py` fixed to avoid duplicate `pThis` for `__thiscall` waves.
  - Applied multiple waves over trade/diplomacy-trade handlers and wrappers.
  - Trade hotflow artifact delta (`batch680_hidden_trade_pre` -> `batch687_hidden_trade_post`):
    - `in_ECX: 146 -> 0`
    - `in_stack_arg: 114 -> 23`
    - rows: `46 -> 5`
  - Remaining trade stack-only residuals captured in `tmp_decomp/batch687_hidden_trade_post.csv`.
- Diplomacy lane normalization (initial broad pass):
  - Baseline: `tmp_decomp/batch688_hidden_diplomacy_pre.csv`
    - `in_ECX=648`, `in_stack_arg=380`, rows=`127`.
  - Applied ECX-only thiscall waves (`ecx>=5`, `ecx>=4`, `ecx>=3`, `ecx>=2`) and targeted manager-signature ABI fixes (`batch689_diplomacy_manager_thiscall_fix.csv`).
  - Post snapshot: `tmp_decomp/batch689_hidden_diplomacy_post.csv`
    - `in_ECX: 648 -> 73`
    - `in_stack_arg: 380 -> 288`
    - rows: `127 -> 60`
- Invariants remained green through the sprint:
  - strict super-lane gate: `0`
  - runtime bridge gate (`0x00600000..0x0062ffff`): `0`
  - counters stable: `total_functions=13835`, `renamed_functions=13835`, `default_fun_or_thunk_fun=0`.

## 2026-02-26 Batch688-Batch690 (diplomacy + script hardening)
- Hardened reusable wave script:
  - `new_scripts/apply_hidden_ecx_fastcall_wave.py`
  - fixed `__thiscall` parameter build to prevent duplicate explicit `pThis`.
- Diplomacy normalization waves:
  - Baseline: `tmp_decomp/batch688_hidden_diplomacy_pre.csv`
    - `in_ECX=648`, `in_stack_arg=380`, rows=`127`.
  - Applied thiscall ECX-only waves (`ecx>=5`, then `>=4`, `>=3`, `>=2`) and a targeted manager ABI correction wave:
    - `batch689_diplomacy_manager_thiscall_fix.csv`
    - `batch689_diplomacy_slot_arg_widen.csv`
  - Applied stack-arg cdecl wave on high-confidence `in_ECX=0` rows:
    - `apply_hidden_param_signature_wave.py` over `batch689_hidden_diplomacy_post.csv`.
  - Post: `tmp_decomp/batch690_hidden_diplomacy_post.csv`
    - `in_ECX: 648 -> 73`
    - `in_stack_arg: 380 -> 207`
    - rows: `127 -> 52`
- Trade lane remained stabilized at `batch687` snapshot:
  - `in_ECX=0`, `in_stack_arg=23`, rows=`5`.
- Gates/counters remained green:
  - strict super-lane `0`
  - runtime bridge unresolved `0`
  - `total_functions=13835`, `renamed_functions=13835`, `default_fun_or_thunk_fun=0`.

## 2026-02-26 Batch690-Batch692 (diplomacy stack-phase)
- Continued diplomacy artifact burn-down from `batch690` baseline:
  - `in_ECX=73`, `in_stack_arg=207`, rows=`52`.
- Added reusable capability:
  - `new_scripts/apply_thiscall_stack_params_from_hidden_csv.py`
  - new flag `--allow-global` to process global-namespace `__thiscall` functions with stack artifacts.
- Applied waves:
  - global `__thiscall` stack-param wave (`allow-global`) over high-confidence rows (`min_stack_hits>=4`, `max_params<=2`): `ok=8`.
  - follow-up `allow-global` wave (`min_stack_hits>=3`, `max_params<=1`): `ok=3`.
- Post snapshot:
  - `tmp_decomp/batch692_hidden_diplomacy_post.csv`
  - `in_ECX=73`, `in_stack_arg=155`, rows=`42`.
- Invariants remained green:
  - strict gate `0`
  - runtime bridge gate `0`
  - progress counters unchanged/stable.

## 2026-02-26 Batch700-Batch706 (trade/dipl cleanup + TradeControl namespace extraction)
- Finished trade+dipl hidden-ABI cleanup lane:
  - trade signature repair wave (`batch700_trade_signature_repair.csv`) applied; residual collapsed to known false-positive `0x0042d240`.
  - diplomacy residual cleanup reached same floor; current trade+dipl scan (`batch706_hidden_diplomacy_trade_post.csv`) shows only:
    - `0x0042d240` stack false-positive,
    - 2 library/MFC ECX artifacts (`0x0060531e`, `0x00618884`).
- Broad hidden-ABI burn-down (map/order lanes):
  - `batch702_hidden_all_pre.csv`: rows=295, `in_ECX=996`, `in_stack_arg=797`.
  - applied conservative waves:
    - `apply_hidden_param_signature_wave.py` (high-confidence cdecl rows),
    - `apply_hidden_ecx_fastcall_wave.py` (`__thiscall`, paired thunk/core, bounded stack params).
  - `batch705_hidden_all_post.csv`: rows=257, `in_ECX=878`, `in_stack_arg=488`.
- TradeControl class extraction in Ghidra:
  - created class namespace `TradeControl` via `batch706_tradecontrol_class.csv`.
  - attached 12 high-confidence callbacks/methods to `TradeControl`:
    - `0x00401b3b`, `0x00583bd0`, `0x00588630`, `0x00588670`, `0x00588690`, `0x00589340`, `0x00589540`, `0x0058a1b0`, `0x0058a3b0`, `0x0058ac80`, `0x0058b0f0`, `0x0058b890`.
  - semantic renames/signature normalization applied for orphan/variant methods:
    - `UpdateBarValuesAndRefresh`, `InvokeSlot1A8NoArg`,
    - `RenderQuickDrawControlWithHitRegionClipVariantA/B/C`,
    - `RenderQuickDrawOverlayWithHitRegionVariantA/B`,
    - `InvokeSlot1CCIfSlot28Enabled`.
- Post-wave gates/counters:
  - strict super-lane gate: 0
  - runtime bridge unresolved gate: 0
  - counters unchanged (`total_functions=13835`, `renamed_functions=13835`, `default_fun_or_thunk_fun=0`).

## 2026-02-26 Batch707 (trade derived-class attachment wave)
- Parsed redecomp trade files (`TAmtBar.cpp`, `TIndustryAmtBar.cpp`, `TRailAmtBar.cpp`, `TShipAmtBar.cpp`, `TTraderAmtBar.cpp`) and attached 14 high-confidence method addresses to concrete class namespaces:
  - `TAmtBar`: `0x00588580`, `0x005885c0`
  - `TIndustryAmtBar`: `0x005891d0`, `0x00589210`, `0x00589260`
  - `TRailAmtBar`: `0x00589f90`, `0x00589fd0`, `0x0058a020`
  - `TShipAmtBar`: `0x0058ab60`, `0x0058aba0`, `0x0058abf0`
  - `TTraderAmtBar`: `0x0058aef0`, `0x0058af30`, `0x0058af80`
- Applied semantic method names + signatures in-class (constructor/destructor/base-state patterns and key behavior methods like `SelectTradeSummaryMetricByTagAndUpdateBarValues`, `UpdateNationStateGaugeValuesFromScenarioRecordCode`).
- TradeControl lane remained attached and normalized (12 methods/callbacks in `TradeControl` namespace).
- Post gates remained green:
  - strict super-lane `0`
  - runtime bridge unresolved `0`
  - counters unchanged (`13835/13835`, default `0`).

## 2026-02-26 Batch708 (TradeControl vtable/ownership/field reconstruction)
- TradeControl vtable reconstruction upgrades:
  - canonicalized missing vtable root:
    - `0x00666ba0 -> g_vtblTTraderAmtBar` (constructor evidence from `0x0058aef0` / `0x0058ae30`).
  - reran `tradecontrol_vtable_recon.py`:
    - base class set (9 classes) now maps fully (`classes_mapped=9`, no missing classes).
    - applied slot labels (`ok=801`) and then attached all unique-owner global targets (`17/17` attached).
  - expanded class set to 13 classes (`+TTradePolicyCluster`, `+TToolBarCluster`, `+T2PictToggleButton`, `+TCloseParentButton`):
    - slot labels added (`ok=356`, `skip=801`),
    - unique-owner thunk targets attached (`6/6`).
    - post-run: `tradecontrol_vtable_attach_candidates.csv` rows = `0`.
- New reusable owner-resolution script:
  - added `new_scripts/resolve_vtable_owner_for_targets.py`.
  - resolves target function -> owner class from DATA slot refs (with JMP-thunk support), emits:
    - `<prefix>_evidence.csv`, `<prefix>_summary.csv`, `<prefix>_attach.csv`.
  - used to classify and attach trade handler implementations:
    - `0x00584320 -> TTradePolicyCluster`
    - `0x005849d0 -> T2PictToggleButton`
    - `0x00584d30 -> TCloseParentButton`
    - `0x00584ea0 -> TToolBarCluster`
    - `0x005851c0 -> TToolBarCluster`
    - `0x0058b7f0 -> THQButton`
    - `0x0058bf50 -> TArmyPlacard`
- Trade range class attachment batch:
  - upgraded `attach_class_methods_by_name_patterns.py`:
    - supports mangled names (`?Construct...@@` parsing),
    - supports `--start/--end` range filters.
  - applied in trade range `0x00583b00..0x0058c200`:
    - attached `73` constructor/destructor/create/get-classname functions to concrete classes.
  - upgraded `attach_class_methods_by_embedded_token.py` with `--start/--end` filtering (for safe scoped dry-runs).
- TradeControl field recovery:
  - upgraded `generate_class_field_candidates.py` to filter vtable-expression false positives (`*(int *)this + 0xNN`).
  - created concrete root struct `/TradeControl` (was 1-byte placeholder) with conservative typed fields:
    - `controlTag@0x1c`
    - `field_34@0x34`
    - `field_38@0x38`
    - `barValue60@0x60`
    - `barSelected62@0x62`
    - `barAux66@0x66`
    - `bitmapId@0x84`
    - `autoRepeatTick94@0x94`
  - decomp now renders named fields (e.g., `this->autoRepeatTick94`, `this->barValue60`, `this->barSelected62`).
- Metrics/gates (post batch708):
  - strict super-lane gate: `0` rows (`tmp_decomp/batch708_strict_gate_post.csv`)
  - runtime bridge unresolved gate: `0` rows (`tmp_decomp/batch708_runtime_gate_post.csv`)
  - counters: `total_functions=13835`, `renamed_functions=13835`, `default_fun_or_thunk_fun=0`, `vtbl_count=234`.

## 2026-02-26 Batch709 (TradeControl lane closure + deep-slot expansion)
- Closed trade-range global `__thiscall` residuals:
  - started from `31` global `__thiscall` functions in `0x00583b00..0x0058c200`.
  - applied owner-driven attachment waves (vtable slot refs + constructor evidence).
  - result: `0` global `__thiscall` functions in that range (`tmp_decomp/batch709_trade_range_global_thiscall_post2.log`).
- Added one missing thunk function used by placard vtable:
  - created `0x0040380a` -> `thunk_WrapperFor_thunk_InvalidateCityDialogRectRegion_At0058bb50` (JMP thunk to `0x0058bb50`).
  - this increased function totals by one (`13835 -> 13836`).
- Attached high-confidence residual handlers/wrappers:
  - bar/cluster/placard/HQ/trader lane attachments from `batch709_trade_remaining_owner_probe_attach.csv`, `batch709_trade_residual_attach.csv`, and `batch709_trade_wrapper_attach.csv`.
  - key class-owner placements included:
    - `TAmtBar`: `ClampAndApplyTradeMoveValue` (+ thunk), `HandleTradeMoveStepCommand` chain.
    - `TIndustryCluster` / `TRailCluster` / `TShipyardCluster`: factory/construct helpers.
    - `TTraderAmtBar`: wrapper `WrapperFor_GetActiveNationId_At0058b070`.
    - `TPlacard` / `TArmyPlacard` / `THQButton`: wrapper/method ownership normalization.
- Trade method demangle pass:
  - applied 18 readable renames from mangled C++ names in trade/placard lane (`batch709_trade_wrapper_demangle_renames.csv`), including:
    - `HandleTradeMoveStepCommand`, `HandleTradeMovePageStepCommand`,
    - `SelectTradeSpecialCommodityAndInitializeControls`,
    - `RefreshTradeMoveBarAndTurnControl`,
    - `HandleTradeMoveArrowControlEvent`,
    - placard wrapper names and plus/minus handler names.
- Field-model expansion:
  - created/updated root class structs with conservative fields:
    - `/TAmtBar`, `/TIndustryAmtBar`, `/TRailAmtBar`, `/TShipAmtBar`, `/TTraderAmtBar`.
  - decomp now shows named members in core methods (e.g., `pOwner20`, `barValue60`, `barSelected62`).
- Deep vtable reconstruction upgrade:
  - reran `tradecontrol_vtable_recon.py` with `max_slots=220`, `max_hole_run=64`.
  - generated 220-slot matrix (`rows=2860`) and applied deep slot labels (`ok=1703`, `skip=1157`).
  - attached 21 additional unique-owner deep-slot thunks (`batch709_tradecontrol_deep_attach_apply.log`).
  - post deep-run attach candidates: `0` (`tradecontrol_vtable_deep_post_attach_candidates.csv`).
- Snapshot after batch709:
  - trade-range globals: `45` total, `0` `__thiscall`, `0` mangled (`tmp_decomp/batch709_trade_globals_snapshot2.log`).
  - counters: `total_functions=13836`, `renamed_functions=13836`, `default_fun_or_thunk_fun=0`, `vtbl_count=234`.
  - gates: strict `0`, runtime bridge unresolved `0`.

## 2026-02-26 Batch711 (TradeControl class quality pass)
- Added reusable scripts:
  - `new_scripts/list_functions_in_range.py` (range inventory with namespace/cc/mangled flags).
  - `new_scripts/list_functions_by_signature_regex.py` (program-wide signature regex triage).
- TradeControl class verification:
  - `tmp_decomp/batch711_tradecontrol_methods_post.csv`: `12` methods in `TradeControl`, all `__thiscall`, no generic names.
  - no residual global functions typed as `TradeControl * this`.
- Fixed mis-owned mangled thunk in trade arrow lane:
  - moved `0x00406965` from `TRailAmtBar` to `TShipyardCluster`,
  - renamed to `thunk_HandleTradeMoveArrowControlEvent`,
  - normalized signatures for `0x00406965` and `0x0058a940` to use `TradeControl * pTradeControl`.
- Extended signature tooling:
  - updated `new_scripts/apply_signatures_from_csv.py` to resolve named project datatypes (not only primitive aliases), allowing class-pointer params in CSV waves.
- Snapshot after batch711:
  - trade-range (`0x00583b00..0x0058c200`) globals: `38`, `__thiscall=0`, mangled=0 (`tmp_decomp/batch711_trade_range_functions_post.log`).
  - strict super-lane gate: `0` (`tmp_decomp/batch711_strict_gate.csv`).
  - runtime bridge unresolved (`0x00600000..0x0062ffff`): `0` (`tmp_decomp/batch711_runtime_gate.csv`).
  - counters unchanged (`13836/13836`, default `0`, vtables `234`).

## 2026-02-26 Batch712 (trade residual globals + thunk island closure)
- Added reusable scripts:
  - `new_scripts/generate_missing_jmp_thunks_for_targets.py` (derive missing low-address JMP thunk entries for selected targets).
  - `new_scripts/list_functions_by_signature_regex.py` (kept for typed-lane audits).
- Improved script robustness:
  - fixed class extraction regex in `resolve_vtable_owner_for_targets.py` for slot symbols with nested `_Slot...` suffixes.
- Trade residual global pass:
  - generated and created 7 missing low-address JMP thunks:
    - `0x00401659 -> 0x0058b460`
    - `0x0040178f -> 0x0058bfe0`
    - `0x004033f0 -> 0x005899c0`
    - `0x0040415b -> 0x0058b750`
    - `0x004056b4 -> 0x00588c30`
    - `0x004086e8 -> 0x0058b4f0`
    - `0x00408891 -> 0x0058b8d0`
  - post-thunk owner probe produced strict unique-owner attachments (7/7):
    - `0x00588c30 -> TAmtBar`
    - `0x005899c0 -> TIndustryAmtBar`
    - `0x0058b460 -> TCivilianButton`
    - `0x0058b4f0 -> TTraderAmtBar`
    - `0x0058b750 -> THQButton`
    - `0x0058b8d0 -> THQButton`
    - `0x0058bfe0 -> TArmyPlacard`
  - attached all 7 new thunk entries to matching classes.
  - attached `0x00584f27 HandleCrossUSmallViewsCommandTagDispatch` to `TToolBarCluster` (split helper called from `DispatchEvent10CommandTagsWithLocalizationGuards`).
- Signature/rename cleanup:
  - applied concrete `__thiscall` signatures for the 7 reattached target methods and 7 newly-created thunks.
  - semantic renames:
    - `0x00588c30 TAmtBar::ApplyMoveValueSlot1D4NoCommit`
    - `0x005899c0 TIndustryAmtBar::ApplyMoveValueSlot1D4NoCommit`
    - `0x0058b460 TCivilianButton::SetSelectionAndEnableByMappedValue`
    - `0x0058b750 THQButton::SetModeAndBitmapBySelectionState`
    - `0x0058b8d0 THQButton::SetSelectionStateAndRefreshBitmap`
- Snapshot after batch712:
  - trade-range globals dropped `38 -> 30`; remaining are shared `thunk_Destruct*` stubs only.
  - trade-range unknown globals dropped to `0`.
  - counters: `total_functions=13843`, `renamed_functions=13843`, `default_fun_or_thunk_fun=0`.
  - strict gate: `0`; runtime bridge gate: `0`.

## 2026-02-26 Batch712b (trade class hygiene + struct expansion)
- Class-method hygiene sweep in trade classes:
  - demangled constructor/destructor/factory names in:
    - `TCivilianButton`
    - `THQButton`
    - `TPlacard`
    - `TArmyPlacard`
  - typed unknown wrappers:
    - `0x0058b6e0` -> `void __thiscall WrapperFor_thunk_NoOpUiLifecycleHook_At0058b6e0(THQButton* this)`
    - `0x0058bab0` -> `void __thiscall WrapperFor_thunk_NoOpUiLifecycleHook_At0058bab0(TPlacard* this)`
- Manual struct layout expansion from create-size evidence + method offset usage:
  - `TCivilianButton` size `0xA0`:
    - `stateCode60@0x60`, `mappedSelection98@0x98`, `selectedValue9c@0x9c`
  - `THQButton` size `0x9C`:
    - `controlWidth34@0x34`, `controlHeight38@0x38`,
    - `modeFlag64@0x64`,
    - `bitmapId90/92/94/96@0x90..0x96`,
    - `selectionState98@0x98`
  - `TPlacard` size `0x94`:
    - `controlWidth34@0x34`, `controlHeight38@0x38`, `placardValue90@0x90`
  - `TArmyPlacard` size `0x94`:
    - `controlWidth34@0x34`, `controlHeight38@0x38`, `placardValue90@0x90`
- Result:
  - decompiler now renders named members in `THQButton`/placard methods (e.g., mode/bitmap/selection fields instead of raw offsets).
  - strict gate remains `0`; runtime gate remains `0`; counters unchanged (`13843/13843`).

## 2026-02-26 Batch713 (industry/rail/shipyard cluster typing lane)
- Cluster signature normalization:
  - `0x00588a30` -> `TIndustryCluster* __cdecl CreateTradeMoveStepControlPanel(void)`
  - `0x00588af0` -> `TIndustryCluster* __thiscall ConstructTradeMoveStepControlPanel(TIndustryCluster* this)`
  - `0x00589660` -> `TRailCluster* __cdecl CreateTradeMoveScaledControlPanel(void)`
  - `0x00589720` -> `TRailCluster* __thiscall ConstructTradeMoveScaledControlPanel(TRailCluster* this)`
  - `0x0058a4d0` -> `TShipyardCluster* __cdecl CreateTradeMoveArrowControlPanel(void)`
  - `0x0058a590` -> `TShipyardCluster* __thiscall ConstructTradeMoveArrowControlPanel(TShipyardCluster* this)`
  - `0x0058a5c0` -> `TShipyardCluster* __thiscall DestructTShipyardClusterMaybeFree(TShipyardCluster* this, byte freeSelfFlag)`
- Cluster struct layouts (manual, conservative):
  - `TIndustryCluster` size `0x90`: `selectedMetric88@0x88`
  - `TRailCluster` size `0x90`: `selectedMetric88@0x88`, `field_8c@0x8c`, `field_8e@0x8e`
  - `TShipyardCluster` size `0x90`:
    - `ownerContext20@0x20`
    - `ownerOffsetX24@0x24`
    - `ownerOffsetY28@0x28`
    - `selectedMetric88@0x88`
    - `selectedMetricMode8c@0x8c`
- Effect on decomp readability:
  - `RefreshTradeMoveBarAndTurnControl` now shows owner-context and owner-offset fields instead of raw offsets.
  - `SelectTradeSpecialCommodityAndInitializeControls` now shows `selectedMetric88`/`selectedMetricMode8c`.
- Invariants:
  - strict gate `0` (`tmp_decomp/batch713_strict_gate.csv`)
  - runtime bridge gate `0` (`tmp_decomp/batch713_runtime_gate.csv`)
  - counters unchanged (`13843/13843`, defaults `0`).

## 2026-02-26 Batch713b (trade-range mangled cleanup wave)
- Added reusable script:
  - `new_scripts/generate_mangled_leaf_renames.py`
    - extracts safe leaf names from MSVC mangled symbols (`?Name@Class@@... -> Name`)
    - handles duplicate leafs in same namespace with `_At<addr>` suffix.
- Applied trade-range demangle rename wave (`0x00583b00..0x0058c200`):
  - `CreateTAmtBarInstance`
  - `CreateTIndustryAmtBarInstance`
  - `CreateTRailAmtBarInstance`
  - `CreateTShipAmtBarInstance`
  - `CreateTTraderAmtBarInstance`
  - `CreateTNumberedArrowButtonInstance`
- Post-check:
  - trade-range mangled functions: `0` (`tmp_decomp/batch713_trade_range_mangled_check.txt`)
  - trade-range globals remain `30`, all shared `thunk_Destruct*` stubs.
- Invariants:
  - strict gate `0` (`tmp_decomp/batch713b_strict_gate.csv`)
  - runtime bridge gate `0` (`tmp_decomp/batch713b_runtime_gate.csv`)
  - counters unchanged (`13843/13843`, defaults `0`).

## 2026-02-26 Batch714/714d/715 (trade helper signature normalization + cluster dtor ownership fix)
- Added/updated reusable scripts:
  - `new_scripts/generate_class_helper_signature_candidates.py`
    - skips namespace/name token mismatches automatically,
    - now includes `Create/Construct*ControlPanelBasic` patterns.
  - `new_scripts/run_unresolved_wave.py`
    - `build_data_type` now resolves named project datatypes from DataTypeManager (not primitives-only fallback).
- Trade helper signature lane:
  - generated helper signature candidates for `0x00583b00..0x0058c200`:
    - `batch714`: 116 rows
    - `batch714d`: 118 rows (includes `TAmtBarCluster` basic control-panel pair)
  - applied signatures with named type resolution:
    - `batch714c`: `ok=86`, `skip=30`
    - `batch714d`: `ok=2`, `skip=116`
  - result: no residual `void*` helper returns for `Create*`/`Construct*`/`Destruct*` in trade range.
- Ownership + signature fixups:
  - moved mis-owned destructor helpers to correct classes:
    - `0x00588b20`: `TAmtBar -> TIndustryCluster`
    - `0x00589760`: `TIndustryAmtBar -> TRailCluster`
  - retyped both as class-owned `__thiscall` destructors returning `this`.
  - retyped `0x0058b070` wrapper first parameter:
    - `void* -> TTraderAmtBar*`.
- Trade-range residual state:
  - globals remain `30` (shared dtor-thunk utilities only).
  - non-getter `void*` signatures reduced to `8` focused handler functions.
- Invariants after batch715:
  - strict gate `0` (`tmp_decomp/batch715_strict_gate.csv`)
  - runtime bridge unresolved `0x00600000..0x0062ffff`: `0` (`tmp_decomp/batch715_runtime_gate.csv`)
  - counters unchanged (`13843/13843`, defaults `0`, vtbl `234`).

## 2026-02-26 Batch716 (trade handler parameter-name normalization lane)
- Applied signature row batch:
  - `tmp_decomp/batch716_trade_handler_param_names.csv`
  - targeted 8 trade handlers that still carry `void*` payloads.
- Scope:
  - normalized event parameter names to consistent dispatcher vocabulary:
    - auto-repeat handlers: `nEventType`, `pEventSender`, `pEventDataA`, `pEventDataB`, `pRepeatArg`
    - panel command handlers: `nEventClass`, `pEventPayload`, `nEventFlags`
  - no speculative concrete payload type changes yet (types remain `void*` where unresolved).
- Result:
  - decomp readability improved in trade input/control flow without ABI risk.
  - residual non-getter `void*` signatures in trade range remain 8 (now with consistent names).
- Invariants:
  - strict gate `0` (`tmp_decomp/batch716_strict_gate.csv`)
  - runtime bridge gate `0` (`tmp_decomp/batch716_runtime_gate.csv`)
  - counters unchanged (`13843/13843`, defaults `0`).

## 2026-02-26 Batch717 (cluster thunk namespace attachment sweep)
- Attached obvious class thunks to owning namespaces:
  - `TIndustryCluster`
    - `0x00401aa0 thunk_DestructTIndustryClusterMaybeFree`
    - `0x0040535d thunk_GetLiteralTypeName_TIndustryCluster`
  - `TRailCluster`
    - `0x00406bae thunk_DestructTRailClusterMaybeFree`
    - `0x00403c83 thunk_GetLiteralTypeName_TRailCluster`
- Purpose:
  - tighten class extraction completeness for industry/rail cluster lanes,
  - improve namespace-scoped browsing without speculative semantics.
- Invariants:
  - strict gate `0` (`tmp_decomp/batch717_strict_gate.csv`)
  - runtime bridge gate `0` (`tmp_decomp/batch717_runtime_gate.csv`)
  - counters unchanged (`13843/13843`, defaults `0`).

## 2026-02-26 Batch718/719 (trade payload typing + class extraction follow-up)
- Event payload typing pass:
  - introduced `PanelEventPayload` and propagated to:
    - `DispatchPanelControlEvent` lane,
    - `DispatchPictureResourceCommand` lane,
    - trade command handlers (`TProductionCluster`, `TAmtBarCluster`, `TAmtBar`, `TIndustryAmtBar`).
  - trade-range non-getter `void*` signatures reduced from `8` to `3` (only auto-repeat handlers remain):
    - `TradeControl::HandleTradeArrowAutoRepeatTickAndDispatch`
    - `TUpDownView::HandleSplitArrowAutoRepeatTickAndDispatch_Offset84`
    - `TRightLeftView::HandleTaggedArrowAutoRepeatTickAndDispatch_Offset84`
- Trade-related class attachment sweep:
  - attached unique-owner thunks:
    - `TRightLeftView::thunk_DestructTRightLeftViewAndMaybeFree`
    - `TUpDownView::thunk_DestructTUpDownViewAndMaybeFree`
    - `TProductionCluster::thunk_DestructTProductionClusterAndMaybeFree`
  - attached 12 unique-owner class-name/literal getter thunks into owning class namespaces
    (`TAmtBar`, `TIndustryAmtBar`, `TRailAmtBar`, `TShipAmtBar`, `TTraderAmtBar`, `THQButton`, `TPlacard`, `TArmyPlacard`, `TUpDownView`, `TRightLeftView`, `TProductionCluster`, `TAmtBarCluster`).
- Struct normalization pass (`/imperialism/classes`):
  - `TradeControl` expanded to include `controlWidth34/controlHeight38/barLimit64`.
  - `TIndustryCluster` and `TRailCluster` expanded from placeholder shells to `0x90` layouts matching active usage.
- Reusable script additions/updates:
  - added `new_scripts/find_decomp_text_matches.py` for scoped decomp regex mining.
  - changed `new_scripts/create_manual_struct_type.py` default datatype category from `/` to `/imperialism/types` to avoid new root-level duplicate type creation.

## 2026-02-26 Batch720 (TradeControl class reconstruction push)
- Method attachment lane:
  - attached 19 high-confidence shared `__thiscall` global vtable targets (owner-class-count 12) into `TradeControl`.
  - attached 20 additional hidden dispatch/thunk pairs into `TradeControl`:
    - low thunk/jmp wrappers (`0x004041a6`, `0x00406a91`, `0x0040740a`, `0x004096d3`, `0x004046d3`, `0x00404de0`, `0x00405b82`, `0x00406014`, `0x00408274`, `0x004088b4`)
    - implementation targets (`0x0048a2e0`, `0x0048a3f0`, `0x0048a3b0`, `0x0048a6d0`, `0x0048aaf0`, `0x0048ab90`, `0x0048abc0`, `0x0048b1a0`, `0x0048b4b0`, `0x0048b690`)
  - renamed wrapper collisions to explicit thunk names:
    - `thunk_DispatchUiCommandToHandler`
    - `thunk_DispatchUiSelectionToHandler`
    - `thunk_DispatchQueuedUiCommandAndRelease`
    - `thunk_DispatchUiCommand19ToParent`
- Signature normalization:
  - applied explicit `TradeControl* this` signatures to the 10 implementation targets above.
  - mirrored readable signatures to wrapper thunks (now decompile as class-thunk forwarders).
- Struct expansion:
  - expanded `TradeControl` in both `/` and `/imperialism/classes` to include:
    - `pChildMapView20@0x20`
    - `pChildControlList44@0x44`
    - `pWindowOwner50@0x50`
  - retained prior known fields (`controlTag`, width/height, bar values, bitmap, auto-repeat tick).
- Result snapshot:
  - `TradeControl` namespace method count: `12 -> 51`.
  - trade-range global residuals remain shared destructor utilities (`30`), unchanged.

## 2026-02-26 Batch721 (TradeControl bulk attachment + struct extension)
- Added reusable script:
  - `new_scripts/generate_single_jmp_thunk_pairs.py`
    - emits `address,target_addr,name,target_name,namespace` for single-JMP wrappers.
- Built vtable-family ownership evidence for trade UI class family and attached high-confidence methods:
  - applied `tmp_decomp/batch721_tradecontrol_attach_owner10plus.csv`
  - result: `ok=55` class attachments to `TradeControl`.
- Built and staged thunk-target attach batch from single-JMP pairs:
  - `tmp_decomp/batch721_tradecontrol_attach_thunk_targets.csv` (`74` targets).
- Expanded `TradeControl` struct in both root and `/imperialism/classes`:
  - added conservative fields:
    - `stateFlag04@0x04`, `stateFlag08@0x08`, `pOwner0c@0x0c`, `stateValue10@0x10`, `pLinkedControl18@0x18`
  - retained previously recovered fields (`controlTag`, geometry, bar values, bitmap, auto-repeat tick).

## 2026-02-26 Batch722 (TradeControl implementation merge + signature cleanup)
- Applied staged thunk-target attachment:
  - `tmp_decomp/batch721_tradecontrol_attach_thunk_targets.csv`
  - result: `ok=74`, `skip=0`, `fail=0`.
- Normalized redundant hidden-this signatures in TradeControl lane:
  - `new_scripts/normalize_thiscall_redundant_pthis.py --apply`
  - result: `ok=14`, `skip=20`, `fail=0`.
  - post-check: `TradeControl * pThis` duplicates reduced to `0`
    (`tmp_decomp/batch722_tradecontrol_redundant_pthis_post.csv`).
- Attached final straggler with `TradeControl* this` still in Global:
  - `0x004d1e60 -> TradeControl`.
- Post-state snapshot:
  - no global functions remain with `TradeControl * this` (`global_count=0` in `tmp_decomp/batch722_tradecontrol_this_all_post.csv`).
  - `TradeControl` namespace method count now `186`
    (`tmp_decomp/batch722_tradecontrol_methods_all.csv`).
- Removed residual opaque impl names in TradeControl lane:
  - renamed six impl/wrapper pairs from `ThunkTargetImpl_*` to behavior-based names:
    - `NoOpControlCallback_Impl`
    - `BuildRectFromControlDimensions_Impl`
    - `DispatchVslot134WithRectAndRectPlus8_Impl`
    - `OffsetRectByControlPositionAndDispatchVslot138_Impl`
    - `OffsetRectByControlPositionAndDispatchVslot138_EcxBridge_Impl`
    - `OffsetRectByControlPosition_Impl`
  - artifact: `tmp_decomp/batch722_tradecontrol_impl_rename.csv`
- Normalized remaining unknown-callconv helpers in TradeControl lane:
  - applied targeted signature CSVs:
    - `tmp_decomp/batch722_tradecontrol_unknown_sigfix.csv`
    - `tmp_decomp/batch722_tradecontrol_unknown_tail_sigfix.csv`
  - result:
    - TradeControl methods by calling convention:
      - `__thiscall=132`, `__cdecl=46`, `__fastcall=6`, `__stdcall=2`, `unknown=0`
      - artifact: `tmp_decomp/batch722_tradecontrol_methods_all_post4.csv`

## 2026-02-26 Batch723 (arrow payload typing + shared base-class split)
- Auto-repeat handler payload typing pass:
  - created `SplitArrowDispatchPayload` (`/imperialism/types`, size `0x8`):
    - `eventToken0@0x0`
    - `axisCoord4@0x4`
  - retyped arrow auto-repeat handlers (and thunk mirrors) to use
    `SplitArrowDispatchPayload * pHitPayload`:
    - `TradeControl::HandleTradeArrowAutoRepeatTickAndDispatch` (+ thunk)
    - `TUpDownView::HandleSplitArrowAutoRepeatTickAndDispatch_Offset84` (+ thunk)
    - `TRightLeftView::HandleTaggedArrowAutoRepeatTickAndDispatch_Offset84` (+ thunk)
    - plus legacy offset-`0x90` helper pair (`0x005839f0` + thunk).
- Shared-method base split (`TradeControl -> TControl`):
  - built strict move batch from 12-owner vtable targets + direct thunk targets:
    - `tmp_decomp/batch723_move_tradecontrol_shared_to_tcontrol.csv`
  - applied namespace attachment:
    - `ok=58`, `skip=0`, `fail=0`
  - post-state:
    - `TControl` method count: `2 -> 60`
    - `TradeControl` method count: `186 -> 128`
    - no global `TradeControl* this` regressions (`global_count=0` maintained).

## 2026-02-27 Batch725 (TradeControl field semantics + redecomp contract)
- Applied behavior-based field semantic renames on both `/TradeControl` and `/imperialism/classes/TradeControl`:
  - `+0x04 -> cityDialogFlag4`
  - `+0x08 -> controlActiveFlag8`
  - `+0x0c -> dialogValueDwordC`
  - `+0x10 -> dialogValueDword10`
  - `+0x18 -> pUiOwner18`
- Added reusable writer script: `new_scripts/rename_struct_fields.py`.
- Verified struct post-state: `tmp_decomp/batch725_tradecontrol_struct_post_semantics.log`.
- Added reusable contract emitter: `new_scripts/generate_tradecontrol_contract.py`.
- Emitted redecomp-ready class contract:
  - `tradecontrol_redecomp_contract.md`
  - sources: `batch723_tcontrol_methods_post_move.csv`, `batch723_tradecontrol_methods_post_move.csv`, `batch724_tradecontract_vtbl_slot_summary.csv`, `batch725_tradecontrol_struct_post_semantics.log`.

## 2026-02-27 Batch726 (Ghidra-first TControl/TradeControl typing pass)
- Extracted concrete `/TControl` and `/imperialism/classes/TControl` layout (size `0x84`) from method evidence; removed 1-byte placeholder.
- Named core TControl fields (`windowHandle1c`, `pChildMapView20`, `pChildControlList44`, `inputEnableFlag4c`, `renderEnableFlag4d`, command-tag defaults at `0x60..0x80`).
- Applied base-lane field names into TradeControl at `+0x4c/+0x4d/+0x5c`.
- Reattached and retyped shared owner-link method to base class:
  - `0x0048a4d0 SetUiResourceOwner -> TControl::__thiscall(TControl* this, TControl* pOwner)`
  - `0x004093d1 thunk_SetUiResourceOwner -> TControl`
- Hidden-ECX signature normalization (TradeControl lane):
  - `OffsetRectByControlPositionAndDispatchVslot138_EcxBridge_Impl` (+ thunk)
  - `OffsetRectByControlPosition_Impl` (+ thunk)
  - `GetCityDialogValueViaChildSlot58` (+ thunk)
  - `SetCityProductionDialogPictureRectAndMaybeRefresh` (+ thunk)
- Refreshed post-wave artifacts:
  - `tmp_decomp/batch726_tcontrol_methods_post.csv` (`rows=62`)
  - `tmp_decomp/batch726_tradecontrol_methods_post.csv` (`rows=126`)
  - `tmp_decomp/batch726_struct_post_trade_tcontrol.log`
  - `tradecontrol_redecomp_contract.md` regenerated from batch726 sources.
- Follow-up class extraction cleanup in same wave:
  - moved additional strict shared core methods from `TradeControl` to `TControl` (slot-consensus distinct=1 across trade-family classes):
    - `GetCityDialogValueViaChildSlot58` (+ thunk)
    - `OffsetRectByControlPositionAndDispatchVslot138_EcxBridge_Impl` (+ thunk)
    - `OffsetRectByControlPosition_Impl` (+ thunk)
- Post-move method counts:
  - `TControl`: `68`
  - `TradeControl`: `120`
- Updated contract artifact to current ownership/signatures:
  - `tradecontrol_redecomp_contract.md` regenerated from `batch726_*post2.csv`.

## 2026-02-27 Batch727 (TradeControl -> TControl ownership collapse wave)
- Ownership evidence lane:
  - ran `resolve_vtable_owner_for_targets.py` across TradeControl `__thiscall` methods.
  - selected high-confidence shared methods with `owner_class_count >= 100`:
    - `27` core methods.
  - included direct thunk mirrors:
    - total move set `58` functions (`27` core + `31` thunks).
- Applied class ownership move:
  - `tmp_decomp/batch727_move_trade_shared_to_tcontrol.csv`
  - result: `ok=53`, `skip=5`, `fail=0`.
- Signature normalization:
  - converted moved signatures to `TControl*` (`this` + matching `pUiElement` arg where present).
  - applied via `tmp_decomp/batch727_sigfix_trade_to_tcontrol_applyfmt.csv`:
    - `planned=58`, `ok=1`, `skip=57`, `fail=0` (most already normalized after namespace move).
- Post-state:
  - `TControl` methods: `126` (`tmp_decomp/batch727_tcontrol_methods_post.csv`)
  - `TradeControl` methods: `62` (`tmp_decomp/batch727_tradecontrol_methods_post.csv`)
  - trade-range global residual unchanged: `30` non-`__thiscall` shared dtor stubs
    (`tmp_decomp/batch727_trade_range_post.csv`).
- Invariants:
  - strict gate `0` (`tmp_decomp/batch727_strict_gate.csv`)
  - runtime bridge unresolved `0x00600000..0x0062ffff`: `0` (`tmp_decomp/batch727_runtime_gate.csv`)
  - counters unchanged (`total=13843`, `renamed=13843`, default `FUN/thunk_FUN=0`).

## 2026-02-27 Batch728 (trade straggler class ownership cleanup)
- Recovered two missing single-JMP thunks in trade lane:
  - `0x00403823 -> 0x00588630` (`thunk_UpdateBarValuesAndRefresh`)
  - `0x00405cc7 -> 0x00588670` (`thunk_InvokeSlot1A8NoArg`)
  - artifact: `tmp_decomp/batch728_create_specific_trade_thunks_apply.log`
- Owner-evidence follow-up:
  - `0x00588630` and `0x00588670` resolve to shared `TAmtBar` family ownership
    (`TAmtBar;TIndustryAmtBar;TRailAmtBar;TShipAmtBar;TTraderAmtBar`).
  - artifacts:
    - `tmp_decomp/batch728_owner_probe_588630_588670_summary.csv`
    - `tmp_decomp/batch728_owner_probe_588630_588670_evidence.csv`
- Applied class re-home batch:
  - moved trade-arrow auto-repeat pair to `TSidewaysArrow`:
    - `0x00583bd0`, `0x00401b3b` thunk
  - moved amt-bar lane to `TAmtBar`:
    - `0x00588630`, `0x00403823` thunk
    - `0x00588670`, `0x00405cc7` thunk
    - `0x00588690`, `0x004038c8` thunk
  - artifact: `tmp_decomp/batch728_move_trade_stragglers.csv`
- Signature normalization:
  - applied explicit `TSidewaysArrow*` / `TAmtBar*` first-arg typing on moved methods/thunks.
  - artifact: `tmp_decomp/batch728_sigfix_trade_stragglers.csv`
- Post-state:
  - `TControl` methods: `126` (`tmp_decomp/batch728_tcontrol_methods_post.csv`)
  - `TradeControl` methods: `57` (`tmp_decomp/batch728_tradecontrol_methods_post.csv`)
  - `TAmtBar` methods: `23` (`tmp_decomp/batch728_tamtbar_methods_post.csv`)
  - `TSidewaysArrow` methods: `5` (`tmp_decomp/batch728_tsidewaysarrow_methods_post.csv`)
  - trade-range residual globals unchanged: `30` shared non-`__thiscall` dtors
    (`tmp_decomp/batch728_trade_range_post.csv`)
- Invariants:
  - strict gate `0` (`tmp_decomp/batch728_strict_gate.csv`)
  - runtime bridge unresolved `0x00600000..0x0062ffff`: `0` (`tmp_decomp/batch728_runtime_gate.csv`)
  - counters: `total_functions=13845`, `renamed_functions=13845`, default `FUN/thunk_FUN=0`
    (`tmp_decomp/batch728_progress_counters.log`)

## 2026-02-27 Batch729/729b (TradeControl shared-tail collapse)
- Owner-probe on remaining TradeControl `__thiscall` methods found only two broad-shared candidates:
  - `0x0048e640 BeginMouseCaptureAndStartRepeatTimer` (`owner_class_count=93`)
  - `0x0048e810 SetControlStateFlagAndMaybeRefresh` (`owner_class_count=96`)
  - artifact: `tmp_decomp/batch729_tradecontrol_owner_probe_summary.csv`
- Moved those methods (and thunks) into `TControl`:
  - `0x0048e640`, `0x0040750e`
  - `0x0048e810`, `0x0040516e`
  - artifact: `tmp_decomp/batch729_move_last_shared_thiscall_to_tcontrol.csv`
- Cleaned obvious leftover thunks targeting `TControl` implementations:
  - `0x00406604`, `0x004d1e60` -> `TControl`
  - artifacts:
    - `tmp_decomp/batch729_move_leftover_thunks_to_tcontrol.csv`
    - `tmp_decomp/batch729_sigfix_leftover_thunks_to_tcontrol.csv`
- Render-lane owner probe (`0x00589340..0x0058b890`) produced no vtable/data-owner evidence; left in `TradeControl` conservatively.
  - artifact: `tmp_decomp/batch729_render_owner_probe_summary.csv` (`rows=0`)
- Post-state:
  - `TControl` methods: `132` (`tmp_decomp/batch729_tcontrol_methods_post2.csv`)
  - `TradeControl` methods: `51` (`tmp_decomp/batch729_tradecontrol_methods_post2.csv`)
  - remaining `TradeControl* this` methods reduced to 7 render-focused entries:
    - `RenderQuickDrawControlWithHitRegionClipVariantA`
    - `RenderQuickDrawOverlayWithHitRegionVariantA`
    - `RenderQuickDrawControlWithHitRegionClipVariantB`
    - `RenderQuickDrawOverlayWithHitRegionVariantB`
    - `RenderQuickDrawControlWithHitRegionClipVariantC`
    - `RenderControlWithTemporaryRectClipRegionAndChildren`
    - `InvokeSlot1CCIfSlot28Enabled`
- Contract updated:
  - `tradecontrol_redecomp_contract.md` regenerated from batch729 post-state (`tcontrol=132`, `tradecontrol=51`).
- Invariants:
  - strict gate `0` (`tmp_decomp/batch729b_strict_gate.csv`)
  - runtime bridge unresolved `0x00600000..0x0062ffff`: `0` (`tmp_decomp/batch729b_runtime_gate.csv`)
  - counters unchanged (`total_functions=13845`, `renamed_functions=13845`, default `FUN/thunk_FUN=0`)
    (`tmp_decomp/batch729b_progress_counters.log`)

## 2026-02-27 Batch730 (render-lane thunk recovery + owner-based class split)
- Recovered missing single-JMP render thunks (writer-safe targeted creation):
  - `0x00408562 -> 0x00589340`
  - `0x00408431 -> 0x00589540`
  - `0x00408b43 -> 0x0058a1b0`
  - `0x00402478 -> 0x0058a3b0`
  - `0x00403ffd -> 0x0058ac80`
  - `0x00405975 -> 0x0058b0f0`
  - `0x00406028 -> 0x0058b890`
  - artifact: `tmp_decomp/batch730_create_render_thunks_apply.log`
- Owner probe after thunk recovery produced strict unique owners for all targets:
  - `RenderQuickDrawControlWithHitRegionClipVariantA` -> `TIndustryAmtBar`
  - `RenderQuickDrawOverlayWithHitRegionVariantA` -> `TIndustryAmtBar`
  - `RenderQuickDrawControlWithHitRegionClipVariantB` -> `TRailAmtBar`
  - `RenderQuickDrawOverlayWithHitRegionVariantB` -> `TRailAmtBar`
  - `RenderQuickDrawControlWithHitRegionClipVariantC` -> `TShipAmtBar`
  - `RenderControlWithTemporaryRectClipRegionAndChildren` -> `TTraderAmtBar`
  - `InvokeSlot1CCIfSlot28Enabled` -> `THQButton`
  - artifact: `tmp_decomp/batch730_render_owner_probe_summary.csv`
- Applied class-owner attachment for targets + thunks:
  - artifact: `tmp_decomp/batch730_move_render_lane_by_owner.csv`
  - result: `ok=14`, `skip=0`, `fail=0`.
- Signatures updated to concrete owner-class pointers (`TIndustryAmtBar*`, `TRailAmtBar*`, `TShipAmtBar*`, `TTraderAmtBar*`, `THQButton*`):
  - artifact: `tmp_decomp/batch730_sigfix_render_lane_by_owner.csv`
- Post-state:
  - `TradeControl` methods: `44` (`tmp_decomp/batch730_tradecontrol_methods_post.csv`)
  - `TControl` methods: `132` (`tmp_decomp/batch730_tcontrol_methods_post.csv`)
  - `TradeControl` has no remaining `__thiscall` methods in `0x00400000..0x005c0000`.
  - class method counts after render split:
    - `TIndustryAmtBar=20`
    - `TRailAmtBar=13`
    - `TShipAmtBar=10`
    - `TTraderAmtBar=14`
    - `THQButton=17`
- Contract updated:
  - `tradecontrol_redecomp_contract.md` regenerated (`tcontrol=132`, `tradecontrol=44`).
- Invariants:
  - strict gate `0` (`tmp_decomp/batch730_strict_gate.csv`)
  - runtime bridge unresolved `0x00600000..0x0062ffff`: `0` (`tmp_decomp/batch730_runtime_gate.csv`)
  - counters: `total_functions=13852`, `renamed_functions=13852`, default `FUN/thunk_FUN=0`
    (`tmp_decomp/batch730_progress_counters.log`)

## 2026-02-27 Batch731 (TView base typing + destructor ownership closure)
- Datatype/base-lane normalization:
  - materialized `TView` as a real 0x60 layout in both datatype roots:
    - `/TView`
    - `/imperialism/classes/TView`
  - seeded fields strictly from constructor/destructor evidence (`ConstructUiResourceEntryBase` / `DestructEngineerDialogBaseState`):
    - offsets include `+0x0c/+0x10/+0x14/+0x18/+0x20/+0x2c/+0x30/+0x3c/+0x44/+0x48/+0x4c/+0x4d/+0x4e/+0x50/+0x54/+0x58/+0x5c`.
- Class ownership closure for non-thunk destructor lane:
  - moved `0x0048a9a0 DestructTViewAndMaybeFree` -> `TView`
  - moved `0x0048a9d0 DestructEngineerDialogBaseState` -> `TView`
  - moved `0x0048e590 DestructTControlAndMaybeFree` -> `TControl`
  - moved `0x00492e10 DestructTControlAndMaybeFree_Impl` -> `TControl`
  - retained already moved thunk mirrors:
    - `0x00404318 -> TView`
    - `0x00407801 -> TControl`
- Signature normalization:
  - `CreateTViewInstance` return typed to `TView*`.
  - `CreateTControlInstance` return typed to `TControl*`.
  - concrete dtor wrapper signatures now class-typed:
    - `TView * __thiscall DestructTViewAndMaybeFree(TView * this, byte freeSelfFlag)`
    - `TControl * __thiscall DestructTControlAndMaybeFree(TControl * this, byte freeSelfFlag)`
- Vtable artifacts:
  - applied TradeControl-family slot labels:
    - `tmp_decomp/batch731_tcontrol_trade_vtbl_apply_slot_summary.csv`
  - post-normalization attach candidates: `0`
    (`tmp_decomp/batch731_tcontrol_trade_vtbl_apply_attach_candidates.csv`).
- Contract/output refresh:
  - regenerated `tradecontrol_redecomp_contract.md` using batch731 artifacts
    (`tcontrol=136`, `tradecontrol=44`).
  - synced contract to redecomp repo:
    - `/home/agluszak/code/personal/imperialism-decomp/docs/tradecontrol_redecomp_contract.md`
- Post-state:
  - `TView` methods: `5` (`tmp_decomp/batch731_tview_methods_post2.csv`)
  - `TControl` methods: `136` (`tmp_decomp/batch731_tcontrol_methods_post2.csv`)
  - `TradeControl` methods: `44` (`tmp_decomp/batch731_tradecontrol_methods_post.csv`)
- Invariants:
  - strict gate `0` (`tmp_decomp/batch731_strict_gate.csv`)
  - runtime bridge unresolved `0x00600000..0x0062ffff`: `0`
    (`tmp_decomp/batch731_runtime_gate.csv`)
  - counters unchanged:
    - `total_functions=13852`
    - `renamed_functions=13852`
    - `default_fun_or_thunk_fun=0`
    - `class_desc_count=406`
    - `vtbl_count=234`
    - `type_name_count=406`
    (`tmp_decomp/batch731_progress.log`)

## 2026-02-27 Batch732/733 (TView/TControl contract + control-tag refresh + trade residual cleanup)
- Generated TView/TControl vtable contract from applied matrix:
  - `tview_tcontrol_vtable_contract.md`
  - extracted override CSVs:
    - `tmp_decomp/batch732_tcontrol_overrides.csv`
    - `tmp_decomp/batch732_derived_overrides.csv`
  - contract summary: `89` slots scanned, `5` TControl overrides, `8` derived overrides, `17` unresolved base/mid slots.
- Refreshed control-tag artifacts and typing lane:
  - `tmp_decomp/batch733_control_tags_detail.csv`
  - `tmp_decomp/batch733_control_tags_summary.csv`
  - `tmp_decomp/batch733_command_tag_dispatch_matrix.csv`
  - enum refresh: `EControlTagFourCC` unchanged (`27` entries).
  - param typing pass touched one remaining signature:
    - `0x005bf740 HandleTradeCommandTagsAndSelectionUpdates` (`commandId -> EControlTagFourCC`).
- Trade-window residual globals cleanup (`0x00583b00..0x0058c200`):
  - annotated all `30` global shared destructor-thunk aliases with explicit non-attachment comment via:
    - `tmp_decomp/batch733_trade_residual_global_comments_fix_tview.csv`
  - preserved canonical name split after correction:
    - `thunk_DestructTViewBaseState`: `20`
    - `thunk_DestructCityDialogSharedBaseState`: `10`
- Invariants/counters (post batch733):
  - strict gate `0`: `tmp_decomp/batch733_strict_gate.csv`
  - runtime bridge unresolved `0x00600000..0x0062ffff` `0`: `tmp_decomp/batch733_runtime_gate.csv`
  - progress unchanged:
    - `total_functions=13852`
    - `renamed_functions=13852`
    - `default_fun_or_thunk_fun=0`
    - `class_desc_count=406`
    - `vtbl_count=234`
    - `type_name_count=406`
    (`tmp_decomp/batch733_progress.log`)

## 2026-02-27 Batch734 (TView/TControl slot71 label normalization)
- Built a focused slot-label pass for the TView/TControl contract lane:
  - copied `ui_widget_shared.h` to `tmp_decomp/batch734_ui_widget_shared_slot71.h` and renamed interface slot `71` only:
    - `CtrlSlot71` -> `BeginMouseCaptureAndStartRepeatTimerSlot11C`
  - reran vtable recon with label apply:
    - `tmp_decomp/batch734_tcontrol_trade_vtbl_apply_matrix.csv`
    - `tmp_decomp/batch734_tcontrol_trade_vtbl_apply_slot_summary.csv`
    - `tmp_decomp/batch734_tcontrol_trade_vtbl_apply_target_summary.csv`
  - apply result: `ok=10`, `skip=880`, `fail=0` (class-family slot labels refreshed in Ghidra).
- Regenerated contract/override artifacts from the updated matrix:
  - `tview_tcontrol_vtable_contract.md`
  - `tmp_decomp/batch734_tcontrol_overrides.csv`
  - `tmp_decomp/batch734_derived_overrides.csv`
- Invariants/counters after batch734:
  - strict gate `0`: `tmp_decomp/batch734_strict_gate.csv`
  - runtime bridge unresolved `0x00600000..0x0062ffff` `0`: `tmp_decomp/batch734_runtime_gate.csv`
  - counters unchanged (`total_functions=13852`, `renamed_functions=13852`, `default_fun_or_thunk_fun=0`, `class_desc_count=406`, `vtbl_count=234`, `type_name_count=406`):
    - `tmp_decomp/batch734_progress.log`

## 2026-02-27 Batch735 (TView/TControl slot68 normalization)
- Extended low-risk vtable interface cleanup for unresolved lane labels:
  - `CtrlSlot68` -> `DerivedOverrideOnlySlot110`
  - retained previous `CtrlSlot71` -> `BeginMouseCaptureAndStartRepeatTimerSlot11C`
  - applied via recon label pass using:
    - `tmp_decomp/batch735_ui_widget_shared_slot68_71.h`
    - `tmp_decomp/batch735_tcontrol_trade_vtbl_apply_matrix.csv`
  - apply result: `ok=10`, `skip=880`, `fail=0`.
- Regenerated contract/override artifacts:
  - `tview_tcontrol_vtable_contract.md`
  - `tmp_decomp/batch735_tcontrol_overrides.csv`
  - `tmp_decomp/batch735_derived_overrides.csv`
- Invariants/counters after batch735:
  - strict gate `0`: `tmp_decomp/batch735_strict_gate.csv`
  - runtime bridge unresolved `0x00600000..0x0062ffff` `0`: `tmp_decomp/batch735_runtime_gate.csv`
  - counters unchanged: `total_functions=13852`, `renamed_functions=13852`, `default_fun_or_thunk_fun=0`, `class_desc_count=406`, `vtbl_count=234`, `type_name_count=406` (`tmp_decomp/batch735_progress.log`).

## 2026-02-27 Batch736 (global slot census tooling)
- Added reusable script:
  - `new_scripts/census_vtable_slots_across_classes.py`
  - purpose: census target functions for selected vtable slot indices across all canonical `g_vtblT*` symbols.
  - outputs:
    - per-slot summary CSV
    - per-slot/per-target counts CSV with sample class entries.
- Ran slot census for unresolved lane candidates (`32,33,38,39,43,45,65,68,71,81,82,83,84,85,86,87,88`):
  - `tmp_decomp/batch736_vslot_census_summary.csv`
  - `tmp_decomp/batch736_vslot_census_targets.csv`
  - `tmp_decomp/batch736_vslot_census.log`
- Findings used for low-risk naming:
  - clear TControl/UI-oriented dominants for slots `65`, `83`, `86`, `88`.

## 2026-02-27 Batch737 (slot bundle normalization from census)
- Applied additional evidence-backed slot label names through vtable recon:
  - `CtrlSlot65` -> `ForwardMapViewVirtualC4IfPresentSlot104`
  - `CtrlSlot83` -> `PaintVisibleChildrenIntersectingClipRectSlot14C`
  - `CtrlSlot86` -> `DispatchUiMouseMoveToChildrenSlot158`
  - `CtrlSlot88` -> `DispatchUiMouseEventToChildrenOrSelfSlot160`
  - retained earlier:
    - `DerivedOverrideOnlySlot110`
    - `BeginMouseCaptureAndStartRepeatTimerSlot11C`
- Artifacts:
  - header input used for mapping: `tmp_decomp/batch737_ui_widget_shared_slot_bundle.h`
  - applied matrix + summaries:
    - `tmp_decomp/batch737_tcontrol_trade_vtbl_apply_matrix.csv`
    - `tmp_decomp/batch737_tcontrol_trade_vtbl_apply_slot_summary.csv`
    - `tmp_decomp/batch737_tcontrol_trade_vtbl_apply_target_summary.csv`
  - apply result: `ok=40`, `skip=850`, `fail=0`.
- Contract refresh:
  - `tview_tcontrol_vtable_contract.md`
  - `tmp_decomp/batch737_tcontrol_overrides.csv`
  - `tmp_decomp/batch737_derived_overrides.csv`
- Invariants/counters after batch737:
  - strict gate `0`: `tmp_decomp/batch737_strict_gate.csv`
  - runtime bridge unresolved `0x00600000..0x0062ffff` `0`: `tmp_decomp/batch737_runtime_gate.csv`
  - counters unchanged: `total_functions=13852`, `renamed_functions=13852`, `default_fun_or_thunk_fun=0`, `class_desc_count=406`, `vtbl_count=234`, `type_name_count=406` (`tmp_decomp/batch737_progress.log`).

## 2026-02-27 Batch738 (unresolved slot expansion + signature normalization)
- Extended evidence-backed unresolved-slot label normalization:
  - `CtrlSlot38` -> `GetCityDialogValueViaChildSlot58Slot98`
  - `CtrlSlot43` -> `HandleCityProductionNoOpSlotAC`
  - `CtrlSlot45` -> `DispatchCityProductionAction1ASlotB4`
  - `CtrlSlot82` -> `AllocateWithFallbackHandlerSlot148`
  - `CtrlSlot85` -> `InvalidateCityDialogRectRegionSlot154`
  - applied through:
    - `tmp_decomp/batch738_ui_widget_shared_slot_bundle2.h`
    - `tmp_decomp/batch738_tcontrol_trade_vtbl_apply_matrix.csv`
  - apply result: `ok=50`, `skip=840`, `fail=0`.
- Regenerated contract + override artifacts:
  - `tview_tcontrol_vtable_contract.md`
  - `tmp_decomp/batch738_tcontrol_overrides.csv`
  - `tmp_decomp/batch738_derived_overrides.csv`
- Slot-driven signature normalization (resolved target lane):
  - normalized selected dominant target wrappers/thunks in `tmp_decomp/batch738_slot_sigfix_correction.csv`.
  - final signature state examples:
    - `HandleCityProductionNoOp`: `void __thiscall ... (TradeControl * this)`
    - `DispatchCityProductionAction1A`: `void __thiscall ... (TControl * this)`
    - `WrapperFor_AllocateWithFallbackHandler_At0048b810`: `void __thiscall ... (TControl * this)`
    - `WrapperFor_InvalidateCityDialogRectRegion_At0048b860`: `void __thiscall ... (TradeControl * this, TControl * pControl)`
- Cluster-field semantics probe:
  - scanned `TAmtBarCluster` for `field_0x8c/0x8e/0x94` direct usage.
  - only direct setter evidence found for `0x8c/0x8e`; no additional read-side semantics in this wave.
  - artifacts:
    - `tmp_decomp/batch738_tamtbarcluster_field8c_hits.csv`
    - `tmp_decomp/batch738_tamtbarcluster_field8e_hits.csv`
    - `tmp_decomp/batch738_tamtbarcluster_field94_hits.csv`
- Invariants/counters after batch738:
  - strict gate `0`: `tmp_decomp/batch738_strict_gate.csv`
  - runtime bridge unresolved `0x00600000..0x0062ffff` `0`: `tmp_decomp/batch738_runtime_gate.csv`
  - counters unchanged: `total_functions=13852`, `renamed_functions=13852`, `default_fun_or_thunk_fun=0`, `class_desc_count=406`, `vtbl_count=234`, `type_name_count=406` (`tmp_decomp/batch738_progress.log`).

## 2026-02-27 Batch739 (cluster field placeholder dehardcode pass)
- Applied conservative cluster field names where direct setter evidence exists:
  - `/imperialism/classes/TAmtBarCluster`
    - `+0x8c -> wordField8c`
    - `+0x8e -> wordField8e`
- Renamed tiny setter helpers + thunk mirrors to match struct fields:
  - `SetTAmtBarClusterWordField8c` (`0x00586a60`)
  - `thunk_SetTAmtBarClusterWordField8c` (`0x004096e2`)
  - `SetTAmtBarClusterWordField8e` (`0x00586ab0`)
  - `thunk_SetTAmtBarClusterWordField8e` (`0x0040324c`)
- Signature correction follow-up from batch738 slot-target cleanup:
  - fixed accidental extra params on `this`-only wrappers/thunks.
  - retained explicit stack parameter only for invalidate wrapper lane:
    - `WrapperFor_InvalidateCityDialogRectRegion_At0048b860(TradeControl * this, TControl * pControl)`.
- Invariants/counters after batch739:
  - strict gate `0`: `tmp_decomp/batch739_strict_gate.csv`
  - runtime bridge unresolved `0x00600000..0x0062ffff` `0`: `tmp_decomp/batch739_runtime_gate.csv`
  - counters unchanged: `total_functions=13852`, `renamed_functions=13852`, `default_fun_or_thunk_fun=0`, `class_desc_count=406`, `vtbl_count=234`, `type_name_count=406` (`tmp_decomp/batch739_progress.log`).

## 2026-02-27 Batch740c/740e/741 (TControl unresolved slot closure lane)
- Batch740c:
  - resolved dominant control-family slot targets from filtered census and renamed:
    - `CtrlSlot32_RootControllerGateDispatch_Impl` (`0x0048a5e0`) + thunk (`0x004036ca`)
    - `CtrlSlot33_NoOp_Impl` (`0x0048a710`) + thunk (`0x00406a37`)
    - `CtrlSlot39_DispatchSlot9CToLinkedChildren_Impl` (`0x0048c820`) + thunk (`0x00402bb7`)
    - `CtrlSlot81_SubtractControlPosFromPoint_Impl` (`0x00427330`) + thunk (`0x004081b1`)
    - `CtrlSlot84_AddControlPosToPoint_Impl` (`0x0048bc30`) + thunk (`0x0040910b`)
    - `CtrlSlot87_CopyRectFromSlot160_Impl` (`0x00429410`) + thunk (`0x00404e08`)
  - artifacts:
    - `tmp_decomp/batch740c_bundle_summary.txt`
    - `tmp_decomp/batch740c_tcontrol_trade_vtbl_apply_slot_summary.csv`
- Batch740e:
  - fixed signature duplication regression in the slot lane (`this,pThis` -> correct `this` form).
  - artifact: `tmp_decomp/batch740e_bundle_summary.txt`
- Batch741:
  - attached the six resolved implementations + six thunks into `TControl` namespace.
  - regenerated matrix/contract with explicit `TView,TControl` class set:
    - `tmp_decomp/batch741_tview_tcontrol_trade_vtbl_apply_matrix.csv`
    - `tmp_decomp/batch741_tview_tcontrol_trade_vtbl_apply_slot_summary.csv`
    - `tview_tcontrol_vtable_contract.md`
  - unresolved base/mid now tracked against full 125-slot contract (`40` unresolved).
- Invariants/counters after batch741:
  - strict gate `0`: `tmp_decomp/batch741_strict_gate.csv`
  - runtime bridge unresolved `0x00600000..0x0062ffff` `0`: `tmp_decomp/batch741_runtime_gate.csv`
  - counters: `total_functions=13858`, `renamed_functions=13858`, `default_fun_or_thunk_fun=0`, `class_desc_count=406`, `vtbl_count=234`, `type_name_count=406` (`tmp_decomp/batch741_progress_snapshot.txt`).

## 2026-02-27 Batch744-750 (fast vtable no-fn thunk-island collapse)
- Dropped strict/runtime gate checks for this lane and ran direct fast waves.
- TView/TControl contract lane:
  - resolved additional unresolved slot stubs and refreshed contract; unresolved base/mid now `22`.
  - artifacts: `tmp_decomp/batch745d_tview_tcontrol_trade_vtbl_apply_matrix.csv`, `tview_tcontrol_vtable_contract.md`.
- Global vtable no-fn cleanup (`slots 0..140`):
  - functionized repeated text-range `<no-fn@...>` addresses in threshold waves (`>=5`, `>=4`, `>=3`, `>=2`) and normalized wrappers to `thunk_*_At<addr>`.
  - recovered stubborn undecoded stubs using patched `new_scripts/create_specific_jmp_thunks_from_csv.py` (now force-disassembles when entry has no decoded instruction).
  - remaining text-range no-fn targets now singleton-only (`max count=1`).
- Counter state after cleanup:
  - `total_functions=14122`
  - `renamed_functions=14122`
  - `default_fun_or_thunk_fun=0`

## 2026-02-27 Batch751 + Batch757 (contract closure + thunk-target semantic lane)
- Batch751 (TView/TControl contract cleanup):
  - Updated `generate_tview_tcontrol_vtable_contract.py` to classify extension/derived-only/trailing-inactive slots as intentional non-gaps.
  - Regenerated matrix + contract artifacts (`tmp_decomp/batch751_*`, `tview_tcontrol_vtable_contract.md`).
  - Result: `potential unresolved base/mid slots = 0`, non-gap extension/abstract slots = `21`.
- Batch757 (semantic pass on recovered thunk-target implementations):
  - Applied behavior-backed renames/signatures for 15 low-risk handlers in `0x0047xxxx..0x0059xxxx` lane.
  - Key renamed targets include:
    - `BlitDibBitsWithStretchDIBits` (`0x0047aae0`)
    - `CreateDibBitmapFromStoredInfo` (`0x0047b280`)
    - `SetWordField90AndMaybeNotify` (`0x00490cb0`)
    - `BusyWaitUntilShiftedTickDeadline` (`0x00493200`)
    - `ApplyDirectionalNudgeAndRefreshDisplay` (`0x00568a40`)
  - Normalized thunk mirror names for `thunk_ThunkTargetImpl_*` / `thunk_Target_*` family (`21` rows in `tmp_decomp/batch757_thunk_mirror_renames.csv`).
  - Counters remain stable after wave (`tmp_decomp/batch757_count_re_progress.log`):
    - `total_functions=14122`, `renamed_functions=14122`, `default_fun_or_thunk_fun=0`.

## 2026-02-27 Batch759/760/761 (remaining thunk-target closure + class-attach sweep + runtime-pointer inventory)
- Batch759:
  - Completed remaining `ThunkTargetImpl_*` semantic renames/signatures:
    - `ReleaseThreeLinkedObjectsAndResetTerrainDescriptorFlags` (`0x004a1eb0`)
    - `UpdateMinisterProductionMetricsForResourceIndex` (`0x004c49f0`)
    - `SetNationRowDisplayValueByDiplomacyPredicate` (`0x004e5a40`)
    - `ApplyDiplomacyRelationMaskToProvinceLinkedObjects` (`0x004e5d90`)
    - `InvokeDialogHooks1D8ThenE4` (`0x00596270`)
  - Normalized related thunk mirrors + wrapper rename; `find_function_addresses --contains ThunkTargetImpl_` now returns count `0`.
- Batch760:
  - Ran class-attachment wave tools:
    - `thiscall-pthis --apply` attached `40` global helpers into owning class namespaces.
    - `thunk-chain --apply` attached `ConstructTArmyBattleBaseStateImpl` to `TArmyBattle` and `DestructCObArray` to `CObArray`.
    - attached `InvokeCurrentMessageFallbackHandler` to `CWnd`.
  - Post-check: `find_thiscall_voidptr_classpass_candidates(min_calls=2,min_ratio=0.80)` returns `0` rows.
- Batch761:
  - Added reusable script: `new_scripts/inventory_runtime_class_ptr_initializers.py`.
  - Emitted runtime-pointer artifacts:
    - `tmp_decomp/batch761_runtime_class_ptr_inventory_symbols.csv`
    - `tmp_decomp/batch761_runtime_class_ptr_inventory_refs.csv`
    - `tmp_decomp/batch761_runtime_class_ptr_inventory_summary.txt`
  - Summary: `ptr_symbol_count=18`, `total_refs=297`, `initializer_like_global_refs=153`.

## 2026-02-27 Batch763-765 (class-attachment cleanup lane + reusable attach tooling)
- Targeted attachment cleanup:
  - attached remaining global typed-`this` functions for `TArmyBattle`, `TCivDescription`, `CWnd`, `CProcessLocalObject`, and `InputState`.
  - verification probes now show:
    - global `__thiscall` signatures with `T* this`: `0`
    - global `__thiscall` signatures with `C* this`: `0`
    - global typed-this attach candidates from reusable scan: `0`.
- Added reusable script:
  - `new_scripts/generate_global_typed_this_attach_candidates.py`
  - purpose: emit safe attach CSV for global `__thiscall` funcs whose first param is already a known class pointer.
- Class-attachment wave tool usage:
  - `thiscall-pthis --apply`: moved 40 functions
  - `thunk-chain --apply`: moved 2 functions (`TArmyBattle`, `CObArray`).
- Runtime pointer owner derivation helper added:
  - `new_scripts/derive_runtime_class_ptr_owner_candidates.py`
  - current output indicates mixed ownership on `PTR_GetCObjectRuntimeClass_0066fec4` (no strong unique owner yet).

## 2026-02-27 Batch769-773 (runtime startup/pointer extraction + struct typing)
- Added reusable probes/recovery scripts:
  - `new_scripts/dump_instructions_window.py`
  - `new_scripts/recover_atexit_init_stubs.py` (now supports optional dtor-stub creation).
- Recovered and normalized runtime startup stubs:
  - init/register-at-exit stubs: `0x00415e20`, `0x0047f710`, `0x0048d240`, `0x00493f90`, `0x004fe6a0`, `0x00576ea0`, `0x005e26d0`, `0x005e29d0`.
  - additional residual init lane: `0x0048d4a0` + guard-dtor helper `0x0048d4d0`.
  - dtor-wrapper stubs recovered from pushed callback addresses: `0x00415e50`, `0x0047f740`, `0x0048d270`, `0x00493fc0`, `0x004fe6e0`, `0x00576ed0`, `0x005e2700`, `0x005e2a00`.
- Runtime-pointer lane semantic renames/signatures:
  - `InitializeUiResourcePoolRuntimeClassFields` (`0x00415f50`)
  - `InitializeRuntimeSelectionRecordArrayRuntimeClassFields` (`0x00480b20`)
  - `InitializeViewModalStateNodeBlockChainRuntimeClassFields` (`0x00492510`)
  - paired destruct wrappers for `0x00646fb0` / `0x0064b580` lanes.
- Struct/global dehardcode pass:
  - created manual structs:
    - `/imperialism/runtime/RuntimeClassState_0063E898`
    - `/imperialism/runtime/RuntimeClassState_00646FB0`
    - `/imperialism/runtime/RuntimeClassState_0064B580`
  - applied typed global labels/comments at:
    - `0x006a13e0` (`g_UiResourcePoolState`)
    - `0x006a15e0` (`g_RuntimeSelectionRecordArrayState`)
    - `0x006a1ac0` (`g_ViewModalStateNodeBlockChainState_006A1AC0`)
    - `0x006a1a40` (`g_TWindowUnlinkDestructState_006A1A40`)
- Enum lane refresh:
  - refreshed `/imperialism/EControlTagFourCC`, `/imperialism/EArrowSplitCommandId`.
  - refreshed gameplay enums and retyped tactical tables (`g_aeTacticalUnitActionClassBySlot`, `g_aeTacticalUnitCategoryBySlot`).
- Progress counters (`tmp_decomp/batch773_count_re_progress.log`):
  - `total_functions=14140`, `renamed_functions=14140`, `default_fun_or_thunk_fun=0`, `class_desc_count=406`, `vtbl_count=234`, `type_name_count=406`.

## 2026-02-27 Batch774-776 (mass no-func linear stub recovery + generic-name cleanup)
- Added reusable residual-coverage scripts:
  - `new_scripts/inventory_no_func_branch_sources.py`
  - `new_scripts/recover_tiny_no_func_linear_stubs.py`
- Function-coverage wave (batch774):
  - recovered tiny linear stubs in large batches (`300 + 300 + 115 + 5` created).
  - `recover_tiny_no_func_linear_stubs.py` now reports `candidates=0` for linear lane.
  - no-func branch inventory dropped from `922` detail rows / `866` grouped starts to `190` / `148` (`tmp_decomp/batch774_no_func_branch_sources_post_*.csv`).
- Generic-name cleanup (batch775):
  - after mass recovery, temporary regression was `default_fun_or_thunk_fun=155`.
  - applied conservative wrapper rename wave:
    - `tmp_decomp/batch775_single_callee_wrapper_renames.csv` (`138` rows applied).
  - applied targeted remaining-17 rename wave (`tmp_decomp/batch775_remaining_fun17_renames.csv`).
  - restored `default_fun_or_thunk_fun=0`.
- Runtime pointer label pass (batch776):
  - renamed pointer labels:
    - `PTR_GetCObjectRuntimeClass_UiResourcePoolState_0063E898`
    - `PTR_GetCObjectRuntimeClass_RuntimeSelectionRecordArrayState_00646FB0`
    - `PTR_GetCObjectRuntimeClass_ViewModalStateNodeBlockChainState_0064B580`
- Counters (`tmp_decomp/batch775_count_re_progress_post17.log`):
  - `total_functions=14860`, `renamed_functions=14860`, `default_fun_or_thunk_fun=0`, `class_desc_count=406`, `vtbl_count=234`, `type_name_count=406`.

## 2026-02-27 Batch777 (owner-empty no-func collapse + locale DAT dehardcode + runtime pointer semantics)
- Added reusable batch script:
  - `new_scripts/functionize_no_func_summary_candidates.py` (functionizes inferred starts from no-func summary CSV with owner-mode filters).
- Coverage wave:
  - functionized owner-empty residual no-func starts in one pass: `created=45`.
  - no-func branch-source inventory reduced to `14` rows, all owner-inside-function singleton islands (`tmp_decomp/batch777_no_func_branch_sources_postfun19_summary.csv`).
- Generic-name cleanup:
  - post-wave temporary regression `default_fun_or_thunk_fun=45`.
  - applied wrapper and targeted behavior-name renames; restored `default_fun_or_thunk_fun=0`.
  - counters now: `total_functions=14931`, `renamed_functions=14931`, `default_fun_or_thunk_fun=0`.
- Signature upgrades on recovered helpers:
  - applied calling-convention/return/param updates for 15 recovered functions (`tmp_decomp/batch777_fun_signature_updates.csv`).
- Locale/state global dehardcode:
  - renamed `DAT_006a83d0/006a8432/006a8400/006a8404/006a8408/006a8424/006a8410/006a8414` to locale numeric/wide-char classification names.
- Runtime pointer lane:
  - fixed `inventory_runtime_class_ptr_initializers.py` matcher to include semantic pointer labels (prefix match).
  - additional pointer semantic renames:
    - `PTR_GetCObjectRuntimeClass_ImperialismApplicationInstanceState_0063E478`
    - `PTR_GetCObjectRuntimeClass_CityDialogModalState_00649A50`
    - `PTR_GetCObjectRuntimeClass_TurnEventDialogFactoryRegistryState_0064B328`
    - `PTR_GetCObjectRuntimeClass_CommandLineParseContextState_0066FEA4`
    - `PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4`
- Batch777 runtime-pointer completion addendum:
  - completed semantic labeling for all remaining raw runtime-class pointers (`PTR_GetCObjectRuntimeClass_*` now all semantic; no raw `<addr>` pointer labels remain).
  - pointer labels added for lanes: `0063E880`, `00648560`, `00648578`, `00648CA8`, `0064BA68`, `0064BA80`, `00650A08`, `00650A50`, `0066FA50`, `0066FA68`.
  - renamed 14 pointer-driven wrapper destructors from generic `WrapperFor_Free*` names to state-specific `Destruct*` names, then applied signature upgrades.
  - renamed CView registry factory/constructor pair:
    - `CreateCViewOwnedBufferRegistryState_00482850`
    - `ConstructCViewOwnedBufferRegistryState_00482950`

## 2026-02-27 Batch778 (no-func closure + runtime-state class extraction)
- Residual no-func normalization:
  - added `new_scripts/classify_no_func_branch_islands.py`.
  - extended `inventory_no_func_branch_sources.py` with `--owner-mode` (`any|empty|nonempty`).
  - verified owner-empty residuals are zero:
    - `tmp_decomp/batch778_no_func_branch_sources_owner_empty_summary.csv` rows=0.
  - classified remaining 14 rows as owner-bound decode islands:
    - `owner_hole_within_span=7`, `owner_tail_island_near_span=7`.
- Runtime/state class extraction wave:
  - created 13 class namespaces for pointer-semantic runtime states and attached methods in bulk:
    - `TRuntimeLinkedBlockChainState_0063E880`
    - `TCityDialogModalState_00649A50`
    - `TTurnEventDialogFactoryRegistryState_0064B328`
    - `TCViewOwnedBufferRegistryState_00648560`
    - `TCViewOwnedBufferChainState_00648578`
    - `TApplicationUiRootControllerState_00648CA8`
    - `TModuleLibraryCacheTableStateA_0064BA68`
    - `TModuleLibraryCacheTableStateB_0064BA80`
    - `TLinkedValueCollectionState_00650A08`
    - `TLinkedBlockChainState_00650A50`
    - `TRuntimeLinkedBlockChainState_0066FA50`
    - `TRuntimeHeapBufferOwnerState_0066FA68`
    - `TCommandLineParseContextState_0066FEA4`
  - added reusable script `new_scripts/create_minimal_class_structs_from_csv.py`.
  - seeded 13 minimal class datatypes in `/imperialism/classes` and propagated typed `pThis` params in class methods.
  - normalized key runtime-state destructor helpers to `__thiscall` with class-pointer params.
- DAT dehardcode follow-up:
  - renamed two high-confidence locale runtime cache globals:
    - `g_Reset_Locale_Name_RuntimeCache_006A83FC`
    - `g_Reinitialize_Locale_Date_RuntimeCache_006A840C`
- Counters remain clean:
  - `total_functions=14931`, `renamed_functions=14931`, `default_fun_or_thunk_fun=0`.
- Batch778 runtime-pointer resolver/script lane:
  - upgraded `derive_runtime_class_ptr_owner_candidates.py` to prioritize `function_namespace` as class-token evidence.
  - regenerated ownership artifacts:
    - strict: `batch778_runtime_class_ptr_owner_strong_ptrs.csv`
    - relaxed: `batch778_runtime_class_ptr_owner_relaxed_strong_ptrs.csv`.
- Batch778 runtime-state signature normalization:
  - converted runtime-state dtor wrappers to `__thiscall` with class-pointer params.
  - applied global cleanup with `normalize_thiscall_redundant_pthis.py` (`ok=19`) to remove duplicated `this,pThis` params.
  - verified no remaining redundant `this,pThis` signatures in runtime-state class namespaces.

## 2026-02-27 Batch779
- Runtime-pointer record typing lane advanced in one serialized pass.
- Added reusable script:
  - `new_scripts/retarget_class_this_pointer_types.py`
- Applied manual struct layouts to runtime-pointer state classes under `/imperialism/classes`:
  - `TModuleLibraryCacheTableStateA_0064BA68` (`0x18`)
  - `TModuleLibraryCacheTableStateB_0064BA80` (`0x18`)
  - `TLinkedValueCollectionState_00650A08` (`0x1c`)
  - `TLinkedBlockChainState_00650A50` (`0x18`)
  - `TRuntimeLinkedBlockChainState_0066FA50` (`0x1c`)
  - `TRuntimeHeapBufferOwnerState_0066FA68` (`0x14`)
- Signature normalization in runtime-pointer init lane:
  - `0x00498f60` `ConstructDataLibraryLoadState` -> `__thiscall`
  - `0x005e4540` `InitializeRuntimeClassVtablePointer_0066FA50_State` -> `__thiscall(this,uint)`
  - `0x005e4780` `InitializeRuntimeClassVtablePointer_0066FA68_State` -> `__thiscall(this)`
- Root type upgrades for module-library cache records to improve decomp readability:
  - `/TModuleLibraryCacheTableStateA_0064BA68` (`0x18`, explicit fields)
  - `/TModuleLibraryCacheTableStateB_0064BA80` (`0x50`, explicit dual-record slots)
- Result: constructor/destructor output around `0x00498f60`, `0x0049ae30`, `0x0049b270` now uses named fields instead of raw index arithmetic.

## 2026-02-27 Batch779 (follow-up)
- Added targeted rename wave for module-cache runtime lane:
  - `ConstructModuleLibraryCacheDualTableState` (+ thunk)
  - `DestructModuleLibraryCacheTableStateBAndFree` (+ thunk)
  - `DestructModuleLibraryCacheTableStateAAndFree` (+ thunk)
- Upgraded root datatypes used by those signatures:
  - `/TModuleLibraryCacheTableStateA_0064BA68` now explicit `0x18` layout
  - `/TModuleLibraryCacheTableStateB_0064BA80` now explicit `0x50` neutral-slot layout
- Kept `/TLinkedValueCollectionState_00650A08` root type at `0x1` (stub) after probe, because forcing `0x1c` root semantics made owner-side arithmetic in `0x005b9fd0` less readable.

## 2026-02-27 Batch780/781 (class harmonization + runtime root/class cleanup)
- Added reusable script: `new_scripts/run_class_harmonization_wave.py` and ran harmonization for `TView/TControl/TradeControl` and targeted runtime class cleanup.
- Hardened reusable scripts:
  - `retarget_class_this_pointer_types.py`: first-parameter rename now uses `this` (prevents duplicate-name collisions).
  - `run_class_harmonization_wave.py`: inserted `sleep(1)` between write phases.
  - `apply_signatures_from_csv.py`: datatype resolver now prefers `/imperialism/classes` over root stubs on name collisions.
- Added reusable script: `new_scripts/move_functions_to_global_namespace_csv.py`.
- Resolved the remaining root/class leakage lane around `TLinkedValueCollectionState_00650A08` by declassifying mis-owned helper pair and normalizing signatures:
  - `0x005b9fd0` -> `AllocateAndPopulateLinkedValueCollectionFromRosterFilter`
  - `0x004010d7` -> `thunk_AllocateAndPopulateLinkedValueCollectionFromRosterFilter`
  - both now `int* __thiscall(..., int rosterIndex, int filterValue)` matching `RET 0x8` arity.
- Runtime root-stub inventory for targeted runtime classes is now clear (`rows=0`): `tmp_decomp/batch781_runtime_root_stub_inventory_post.csv`.

## 2026-02-27 Batch781b (nation-metrics dispatch lane bootstrap)
- Labeled dispatch table base `0x0066d9f0` as `g_apfnNationMetricsAndRosterDispatchTable_0066D9F0`.
- De-orphaned and renamed key `0x005b97xx..0x005ba0xx` entries and thunk mirrors to behavior names.
- Applied high-confidence signature cleanup in this lane:
  - `SetNationMetricCellValueByIndex`
  - `RunNationMetricPreUpdatePassAcrossSecondaryNations`
  - `BuildNationMetricBucketsAndWeightedTrendScores`
  - `IsNationMetricCellNegative` / `IsNationMetricCellPositive`
  - `SelectPreferredNationMetricCodeFromLookup`
- Labeled lookup table `0x0066d810` as `g_ausNationMetricPreferredCodeLookup_0066D810`.

## 2026-02-27 Batch782 (runtime-state field semantics + nation-metrics dispatch disambiguation)
- Runtime-state class field pass:
  - renamed/typed `TRuntimeLinkedBlockChainState_0063E880` core chain fields (`pNodeHead_04`, `pNodeTail_08`, `nNodeCount_0C`, `nNodeCapacity_10`, `pNodeBlockChainHead_14`).
  - renamed/typed `TCViewOwnedBufferChainState_00648578` core chain fields (same pattern as above).
  - renamed/typed key `TCViewOwnedBufferRegistryState_00648560` offsets (`0x40..0x64`, `0x6c`, `0x70`, `0x74`, `0x90`) and normalized ctor/dtor naming/signatures.
- Nation-metrics dispatch lane:
  - added reusable probes:
    - `new_scripts/inventory_code_refs_to_address_range.py`
    - `new_scripts/inventory_data_dword_values_in_range.py`
  - no direct owner refs found for `0x0066d9f0..0x0066da18` yet (`rows=0` in both code-range and data-value scans).
  - disambiguated duplicate thunk lane naming around `0x005b98d0` / `0x005b9b30`:
    - `BuildEligibleNationMetricBucketsAndWeightedTrendScores` (+ thunk `0x00405948`)
    - `BuildSecondaryNationMetricBucketsAndWeightedTrendScores` (+ thunk `0x00404fd4`)
  - normalized hidden-`this` signatures for `RunNationUpdatePassesAndResetTransitionFlags` and eligible/secondary metric builders.
  - labeled dispatch table slots `0x0066d9f0..0x0066da18` and created enum `/imperialism/ENationMetricsDispatchSlot`.

## 2026-02-27 Batch783 (nation-metrics nearby orphan dehardcode)
- De-orphaned adjacent helper cluster in `0x005b9000..0x005ba300` with behavior names/signatures:
  - `GetNationMetricBucketValueByIndex` (`0x005b9030`)
  - `ApplyDiplomacyTransferEffectsAcrossNationMetricRoster` (`0x005b9060`)
  - `RebuildNationMetricPassesAndClampRowsByBaseline` (`0x005b9410`)
  - `CompareNationMetricRowsForSort` (`0x005ba260`)
- Fixed dispatch-lane name collision and clarified split roles:
  - `BuildEligibleNationMetricBucketsAndWeightedTrendScores` (`0x005b98d0`) + thunk `0x00405948`
  - `BuildSecondaryNationMetricBucketsAndWeightedTrendScores` (`0x005b9b30`) + thunk `0x00404fd4`
- Normalized hidden-`this` signatures for:
  - `RunNationUpdatePassesAndResetTransitionFlags` (`0x005b97c0`, thunk `0x004018e3`)
  - both metric-bucket builders above.

## 2026-02-27 Batch785 (runtime locale/stream dehardcode + TradeControl vtable probe)
- Added reusable analysis script:
  - `new_scripts/find_pointer_table_clusters_for_targets.py`
  - purpose: scan contiguous pointer-table clusters for a target function-set (used for TradeControl vtable hunting).
- TradeControl lane probe:
  - ran `tradecontrol_vtable_recon.py` with `TView/TControl/TradeControl` + derived controls.
  - `TradeControl` still has no direct canonical `g_vtblTradeControl` symbol match.
  - pointer-cluster scan over TradeControl method set found only repeated 4-slot runs (`NoOpTurnEventStateVtableSlot0C/10` + `HandleCityDialogNoOpSlot14/18`) across many `.rdata` vtables; no larger unique TradeControl-owned table recovered in this pass.
- Runtime global dehardcode wave (high-confidence, usage-backed):
  - `0x0069be08` -> `g_pStringSharedStaticHeader_0069BE08`
  - `0x0069f1c0` -> `g_pStreamCriticalSectionTableBase_0069F1C0`
  - `0x0069f420` -> `g_pStreamCriticalSectionTableLimit_0069F420`
  - `0x0069c9c8` -> `g_pLocaleNameTableSharedSentinel_0069C9C8`
  - `0x0069ca74` -> `g_pActiveLocaleNameTable_0069CA74`
  - `0x006a83fc` -> `g_pOwnedLocaleNameTable_006A83FC`
  - `0x006a5f40` -> `g_RuntimeLinkedBlockChainState_006A5F40` (typed as `/imperialism/classes/TRuntimeLinkedBlockChainState_0066FA50`)
- Signature normalization:
  - `EnterStreamCriticalSection` (`0x005edbc0`) -> `void __cdecl(..., uint pStreamCriticalSection)`
  - `LeaveStreamCriticalSection` (`0x005edc30`) -> `void __cdecl(..., uint pStreamCriticalSection)`
- TradeControl layout follow-up (safe subset from `TView` base alignment):
  - updated `/TradeControl` and `/imperialism/classes/TradeControl` fields:
    - `+0x4e -> viewField4e` (`ushort`)
    - `+0x54 -> viewField54` (`ushort`)
    - `+0x58 -> sharedStringRef` (`uint`)
    - `+0x5c -> viewField5c` (`uint`)
- Post-batch counters/gates:
  - `total_functions=14931`, `renamed_functions=14931`, `default_fun_or_thunk_fun=0`
  - strict super-lane gate rows = `0`
  - runtime bridge unresolved rows = `0`

## 2026-02-27 Batch786 (runtime locale/stream struct typing + nation dispatch prelude cleanup)
- Tooling:
  - extended `new_scripts/apply_global_data_from_csv.py` to resolve named datatypes (not only builtins), including pointer/array forms like `TType*` and `TType[N]`.
  - added concrete type `/imperialism/types/TLocaleDateTimeNameTable43` (`0xAC`, 43 pointer slots).
  - added concrete type `/imperialism/types/TCrtFileStreamState` (`0x20`, FILE-like stream record).
- Runtime locale lane (high-confidence dehardcode):
  - globals:
    - `g_LocaleDateTimeNameTableSharedDefault_0069C9C8` typed as `TLocaleDateTimeNameTable43`.
    - `g_pActiveLocaleDateTimeNameTable_0069CA74` typed as `TLocaleDateTimeNameTable43*`.
    - `g_pOwnedLocaleDateTimeNameTable_006A83FC` typed as `TLocaleDateTimeNameTable43*`.
  - function renames/signatures:
    - `RebuildActiveLocaleDateTimeNameTableAndAdoptOwnedBuffer` (`0x005f5e50`)
    - `InitializeLocaleDateTimeNameTable` (`0x005f5f00`)
    - `FreeLocaleDateTimeNameTableEntries43` (`0x005f6280`)
    - `AdoptLocaleDateTimeNameTableAsActiveAndOwned` (`0x005f5e9c`)
    - `ResetActiveLocaleDateTimeNameTableToSharedDefault` (`0x005f5ec9`)
    - propagated `TLocaleDateTimeNameTable43*` into:
      - `ExpandDateTimeFormatDirectiveToBuffer`
      - `BuildLocaleTimeFormatPatternString`
      - `InitializeLocaleDateTimeNameTable`
      - `FreeLocaleDateTimeNameTableEntries43`
    - kept `FormatBufferWithPercentDirectivesAndLocaleLock` override param as `void*` to avoid decompiler regression from reused stack-slot counter.
- Runtime stream lane:
  - `g_aCrtFileStreamStateTable_0069F1C0` typed as `TCrtFileStreamState[20]` (0x280 bytes).
  - labeled `0x0069f420` as `g_pCrtFileStreamStateLastEntry_0069F420`.
- Nation-metrics prelude table cleanup:
  - typed/labeled prelude table: `g_apfnNationMetricDispatchPreludeTable_0066D9D0` (`void*[8]`) and slot labels `00..07`.
  - de-orphaned table targets and mirrors:
    - `ComputeNationMetricDispatchScoreAndResolveScale` (+ thunk)
    - `GetNationMetricRosterWordAtOffset0E` (+ thunk)
    - `GetNationMetricRosterWordAtOffset0C` (+ thunk)
    - `ResolveNationMetricScaleFromCodeOrRosterWordAtOffset0A` (+ thunk)
  - applied signatures to small helper targets to remove orphan/no-call noise.
- Post-batch invariants:
  - `total_functions=14931`, `renamed_functions=14931`, `default_fun_or_thunk_fun=0`
  - strict super-lane gate rows = `0`
  - runtime bridge unresolved rows = `0`

## 2026-02-27 Batch789 (signature recovery + constructor lane cleanup)
- Repaired over-broad helper-signature fallout in constructor-heavy class methods.
- Applied `fix_hidden_this_in_class_methods.py --class-regex '^T' --apply` and normalized redundant `this,pThis` (`normalize_thiscall_redundant_pthis.py`).
- Recovered missing stack params via hidden-artifact CSV waves:
  - `apply_thiscall_stack_params_from_hidden_csv.py` (constructor-focused, gapped-slot enabled).
  - `apply_class_method_stack_params_from_hidden_csv.py` for residual cdecl class constructors (`TTechItemLine`, `TMiniCivLine`).
- Targeted signature fixups:
  - `TArmyCheckBox::ConstructTArmyCheckBoxBaseState` (both sites) bootstrapped to class-aware `__thiscall`, then stack params propagated.
  - `TDeluxeText::ConstructTDeluxeTextBaseState` extended to include missing `arg6` used via `in_stack_00000018`.
- Constructor hidden-param scan reduced from 19 rows to 2 residual rows (only `ConstructTMapKeyBaseState_Impl` stdcall helpers).
- Small follow-up class-this typing pass (`apply_class_this_param_types.py --all-classes --apply`): `ok=4`.
- Post-wave invariants:
  - strict super-lane rows = `0`
  - runtime bridge unresolved rows (`0x00600000..0x0062ffff`) = `0`
- Progress counters unchanged at high level:
  - `total_functions=14931`, `renamed_functions=14931`, `default_fun_or_thunk_fun=0`
  - `class_desc_count=406`, `vtbl_count=234`, `type_name_count=406`

## 2026-02-27 Batch790 (Cluster unresolved burn-down)
- Added reusable script:
  - `new_scripts/generate_cluster_impl_names_from_unresolved_snapshot.py`
- Ran high-volume unresolved cleanup on `Cluster_*` rows from `batch789_unresolved_main.csv`:
  - first anchor wave (`min_named_callees=2`): `76` renames applied.
  - second anchor tail (`min_named_callees=1`): `9` renames applied.
  - single-JMP cluster thunk cleanup waves: `8` + `1` renames applied.
  - final tail singleton rename: `1`.
- Net result in main unresolved snapshot (`0x00400000..0x006fffff`):
  - `114` -> `0` rows.
- Post-wave invariants:
  - strict super-lane rows = `0`
  - runtime bridge unresolved rows (`0x00600000..0x0062ffff`) = `0`
- Counters unchanged structurally:
  - `total_functions=14931`, `renamed_functions=14931`, `default_fun_or_thunk_fun=0`
  - `class_desc_count=406`, `vtbl_count=234`, `type_name_count=406`

## 2026-02-27 Batch791/792 (turn-instruction full typing + class attachment + DAT cluster dehardcode)
- Turn-instruction lane:
  - applied full `STurnInstruction_*` signature wave to all 26 dispatch commands using `batch447_tabsenu_loader_bindings_extended.csv`:
    - includes previously missing commands `pric`, `prov`, `tbar`, `tclr`, `coun`.
  - refreshed core dispatch typing with `create_turn_instruction_types.py`:
    - `/imperialism/ETurnInstructionTokenFourCC`
    - `/imperialism/ETurnInstructionDispatchIndex`
    - table typing at `0x00662978` and `0x00698b50`.
- Class extraction/ownership lane:
  - generated `tmp_decomp/batch792_global_typed_this_attach_candidates.csv` and attached all rows:
    - `attach_functions_to_class_csv.py ... --apply`
    - result: `ok=166 skip=0 fail=0`.
  - follow-up check: `generate_global_typed_this_attach_candidates.py` now returns `rows=0` (safe typed-first-param global attach backlog cleared).
- Runtime DAT dehardcode lane:
  - isolated city-building hover/control coordinate cluster from `InitializeCityBuildingHoverSelectionRects_004b95c0`.
  - applied 30-row global rename/type batch (`ushort`) over `0x0069619c..0x006961da`:
    - `tmp_decomp/batch792_citybuild_coordword_renames.csv`
    - applied via `apply_global_data_from_csv.py --apply` (`ok=30`).
  - post-check: unresolved `DAT_*` with `code_refs>=2` in `0x00600000..0x006fffff` reduced to `0`.
- Coverage/invariants:
  - direct-branch functionization probe remains clean: `functionize_missing_branch_targets.py` -> `candidates=0`.
  - no-owner branch-island inventory remains clean: `inventory_no_func_branch_sources.py --owner-mode empty` -> `rows=0`.
  - strict super-lane gate: `rows=0`.
  - runtime bridge unresolved (`0x00600000..0x0062ffff`): `rows=0`.
  - counters:
    - `total_functions=14931`
    - `renamed_functions=14931`
    - `default_fun_or_thunk_fun=0`
    - `class_desc_count=406`, `vtbl_count=234`, `type_name_count=406`.

## 2026-02-27 Tooling workflow update (repo restructure)
- Switched canonical execution path to maintained CLI commands via `uv run impk`.
- Updated `AGENTS.md`:
  - `new_scripts/` treated as legacy compatibility only.
  - new/extended functionality must be added under `src/imperialism_re/commands/` + `command_catalog.yaml`.
  - explicit anti-duplication guidance added (extend existing commands with flags instead of creating parallel variants).
- Added queued consolidation item in `TODO.md` to keep tooling migration explicit and prevent throwaway script drift.

## 2026-02-27 — Datatype Policy Gate + Trade/Dialog Signature Normalization
- Added datatype-root policy gating into `run_wave_bundle` (pre/post checks for forbidden legacy roots, summary counters, failure code on violations).
- Updated active docs/queue references to canonical `/imperialism/...` in `TODO.md` and historical notes in `agent_2.md` where they refer to current datatype paths.
- Applied signature normalization batch for trade/dialog handlers:
  - `0x004f2e00`, `0x004f3050`, `0x004f3370`, `0x004f3710` now use `PanelEventPayload*` event records and explicit `InterNationEventCode` event-code params.
  - `0x0058a940`, `0x005bf740` corrected to `commandId:int` + `PanelEventPayload*` command/event payloads.

## 2026-02-27 — Wave A continuation (UI command-event signatures)
- Normalized additional command-event handlers to typed payload signatures:
  - `0x004ad7a0` `HandleMapContextPrevNextInfoCommands(void*, int, PanelEventPayload*)`
  - `0x00503ed0` `HandleNameSlotNextPrevToggleCommands(void*, int, PanelEventPayload*)`
  - `0x0054e1f0` `HandleNationStatusDialogCommand(void*, int, PanelEventPayload*, int)` (removed incorrect `EControlTagFourCC` param type)
  - `0x0056cd10` `HandleLoadSaveSlotControlSelectionAndQueueOkay(void*, int, PanelEventPayload*)`
  - `0x005779c0` `HandleRandomMapNationPlanAndFlagCommands(void*, int, PanelEventPayload*)`
- Verified decomp now uses `pPanelEvent->controlTag1c` directly in these handlers instead of raw pointer arithmetic.

## 2026-02-27 — Wave A/B/C closure (command-event typing + enum propagation + class ownership)
- Wave A closure:
  - completed command-event signature normalization across trade/diplomacy/dialog handlers from the active queue.
  - verified key handlers keep typed `PanelEventPayload*` access and no regression to raw `*(int *)(param + 0x1c)` patterns in touched functions.
- Wave B closure:
  - refreshed enums:
    - `create_control_tag_enum` from focused trade/dialog summary (`entries=37`).
    - `create_arrow_command_enum` (`/imperialism/EArrowSplitCommandId`).
  - propagated enum typing into payload structs:
    - `/PanelEventPayload +0x1c` `controlTag1c: uint -> EControlTagFourCC`.
    - `/imperialism/types/SplitArrowDispatchPayload +0x0` `eventToken0: uint -> EArrowSplitCommandId`.
  - decomp now renders control-tag comparisons symbolically (example: `CONTROL_TAG_THGR`, `CONTROL_TAG_TFEL`, `CONTROL_TAG_YAKO`) in touched handlers.
- Wave C closure:
  - added maintained command `attach_functions_to_class_csv` and registered it in `command_catalog.yaml`.
  - attached remaining high-confidence global arrow handlers using thunk/vtable owner evidence:
    - `0x005839f0 -> TArrowsControl::HandleSplitArrowAutoRepeatTickAndDispatch_Offset90`
    - `0x0058c640 -> TNumberedArrowButton::HandleSplitArrowMousePhaseStateAndDispatchCommand64or65`
  - post-check: no remaining global methods with typed `this` pointers for `TView/TControl/TradeControl/TArrowsControl/TNumberedArrowButton` (`rows=0` in `batch_waveC_global_class_this_post.csv`).
- Tooling upgrade used in this wave:
  - extended `rename_struct_fields` to accept full datatype-path overrides, enabling direct enum-field typing (for example `0x1c:/imperialism/EControlTagFourCC:controlTag1c`).
- Post-wave counters:
  - `total_functions=14931`
  - `renamed_functions=14931`
  - `default_fun_or_thunk_fun=0`
  - `class_desc_count=406`
  - `vtbl_count=234`
  - `type_name_count=406`
  - datatype root policy remains clean: forbidden `/Imperialism` violations=`0`.

## 2026-02-27 — Split-arrow ABI lane start (post-queue reprioritization)
- Reprioritized `TODO.md` active queue to put split-arrow callback ABI normalization first.
- Applied focused signature normalization batch:
  - `0x0058c640` -> `TNumberedArrowButton::HandleSplitArrowMousePhaseStateAndDispatchCommand64or65(TNumberedArrowButton*, int mousePhase, void*, void*, SplitArrowDispatchPayload*, void*)`
  - `0x005869c0` -> `TProductionCluster::HandleProductionClusterValuePanelSplitArrowCommand64or65AndForward(TProductionCluster*, EArrowSplitCommandId commandId, PanelEventPayload*, int)`
- Added explicit function comments (ABI notes) documenting that decompiler `unaff_retaddr` corresponds to callback stack arg 1 semantics in both handlers.
- Verification:
  - disassembly confirms stack-purge and argument shape remain stable (`RET 0x14` for `0x0058c640`, `RET 0x0c` for `0x005869c0`).
  - decompiler artifact `unaff_retaddr` still appears in these two functions; item remains active for deeper parameter-ID recovery.

## 2026-02-28 — Enum wave tooling + first applied wave
- Committed enum-pipeline tooling (`c301200`):
  - candidate extraction/build/apply/verify commands registered in catalog.
  - `create_gameplay_enums` now supports multi `--spec-json` merge.
  - `apply_signatures_from_csv` now reports unresolved enum-like type refs.
- Extended `extract_enum_domain_candidates` with instruction evidence lane:
  - captures `PUSH imm -> CALL` sequences (`kind=call_arg_immediate`, `evidence_type=push_call`).
  - this recovered split-arrow command constants where compare/switch extraction had zero coverage.
- Added reusable orchestration command:
  - `run_enum_domain_wave` (extract -> build spec -> optional apply -> verify).
- Ran and applied a real wave (`batch_enum_waveC_apply`) on `arrow_command + control_tag` domains over `0x00500000..0x005fffff`:
  - candidates: 36, inferred enums: 2 (`EArrowSplitCommandId`, `EControlTagFourCC`).
  - applied enum parameter propagation: `ok=5` (`nEventClass`/`arg1` in trade/map handlers).
  - post-verify hotspots: 0.

## 2026-02-28 — Enum propagation continuation (diplomacy + map mode)
- Added and used `run_enum_domain_wave` for multi-lane propagation without per-step manual command chains.
- Diplomacy lane (`enum_domains_diplomacy.csv`, `0x00500000..0x0062ffff`):
  - extracted 65 candidates across relation/action/proposal raw domains.
  - applied 1 additional enum param type (`ApplyJoinEmpireMode0GlobalDiplomacyReset_Impl(arg1 -> EDiplomacyActionCodeRaw)`).
  - post-wave hotspots: 0.
- Map interaction mode strict lane (`enum_domains_mapmode_strict.csv`):
  - extracted 25 candidates.
  - applied 2 enum param types:
    - `SetModeAndBitmapBySelectionState(mode -> EMapInteractionMode)`
    - `SetSelectionStateAndRefreshBitmap(mode -> EMapInteractionMode)`
  - post-wave hotspots: 0.
- Safety hardening:
  - `create_gameplay_enums` now merges incoming specs with existing enum members and preserves existing member names on conflicts.
  - size selection now prefers existing observed enum sizes (including legacy aliases) instead of forcing inferred size.
- Enum wave runner improvements:
  - added `--skip-create-enums` and `--fail-on-hotspots` flags to `run_enum_domain_wave` for safer/faster propagation passes.
  - smoke-validated on strict map-mode domain (`batch_enum_waveK_smoke`): 21 candidates, 0 hotspots.
- Added reusable domain packs under `config/enum_domains/`:
  - `core_callbacks.csv`, `diplomacy_raw.csv`, `map_mode_strict.csv`, `all_high_confidence.csv`, `turn_instruction_token.csv`.
- Ran consolidated high-confidence dry/apply waves:
  - dry (`batch_enum_waveM_all_dry`) narrowed to 1 hotspot after arrow-domain regex tightening.
  - apply (`batch_enum_waveN_all_apply`) propagated final hotspot:
    - `HandleTransportPictureSplitArrowCommand64or65(splitCommandId -> EArrowSplitCommandId)`.
  - post-wave hotspots: 0.
- Expanded extractor compare parser to accept quoted FourCC literals (`'xxxx'`) in compare/switch patterns.
- Turn-instruction token lane probe (`batch_enum_waveP_turn_token_dry`) still yields 0 candidates; current dispatch flow likely compares streamed locals/table lookups rather than handler params.
- Extractor enhancement:
  - `extract_enum_domain_candidates` now parses quoted FourCC literals in compares/switch (`'xxxx'`) and can emit `struct_field` candidate rows from `this->field` compare evidence when class struct offsets are resolvable.
  - current probe on strict map-mode lane still produced param-only candidates (no struct-field hits yet).
- Added `config/enum_domains/turn_event_factory_slot.csv` and ran strict probe wave (`batch_enum_waveR_turnevent_dry`):
  - 1 candidate found (`call_arg_immediate` in `HandleTurnEventCodes28_2E_2F_30_31_32`), no param/struct propagation targets.
  - no hotspots.
