# TradeControl Redecomp Contract

## Sources
- struct: `tmp_decomp/batch731_structs_post.log` (`/TradeControl`)
- TControl methods: `tmp_decomp/batch731_tcontrol_methods_post2.csv`
- TradeControl methods: `tmp_decomp/batch731_tradecontrol_methods_post.csv`
- vtable slot summary: `tmp_decomp/batch731_tcontrol_trade_vtbl_apply_slot_summary.csv` (first `123` slots)

## Field Layout
- type: `/TradeControl`
- size: `0x98`

| Offset | Name | Type |
|---|---|---|
| `+0x00` | `pVtable` | `void *` |
| `+0x04` | `cityDialogFlag4` | `uint` |
| `+0x08` | `controlActiveFlag8` | `uint` |
| `+0x0c` | `dialogValueDwordC` | `uint` |
| `+0x10` | `dialogValueDword10` | `uint` |
| `+0x18` | `pUiOwner18` | `void *` |
| `+0x1c` | `controlTag` | `uint` |
| `+0x20` | `pChildMapView20` | `void *` |
| `+0x24` | `controlPosX24` | `uint` |
| `+0x28` | `controlPosY28` | `uint` |
| `+0x2c` | `cachedPosX2c` | `uint` |
| `+0x30` | `cachedPosY30` | `uint` |
| `+0x34` | `controlWidth34` | `uint` |
| `+0x38` | `controlHeight38` | `uint` |
| `+0x44` | `pChildControlList44` | `void *` |
| `+0x4c` | `inputEnableFlag4c` | `byte` |
| `+0x4d` | `renderEnableFlag4d` | `byte` |
| `+0x50` | `pWindowOwner50` | `void *` |
| `+0x5c` | `inputGateOverride5c` | `uint` |
| `+0x60` | `barValue60` | `ushort` |
| `+0x62` | `barSelected62` | `ushort` |
| `+0x64` | `barLimit64` | `ushort` |
| `+0x66` | `barAux66` | `ushort` |
| `+0x84` | `bitmapId` | `ushort` |
| `+0x94` | `autoRepeatTick94` | `uint` |

## Method Signatures

### TControl primary (`67`)
| Address | Signature |
|---|---|
| `0x00402888` | `void __cdecl DestructTControlAndMaybeFree_Impl(void)` |
| `0x00406429` | `int __thiscall DispatchUiMouseEventToChildrenOrSelf(TControl * this, int param3, int param4, int param5, int param_4)` |
| `0x00415d70` | `void __thiscall SetCityDialogValueDword10(TControl * this, int value)` |
| `0x00427220` | `void __thiscall NoOpCommandHandler(TControl * this)` |
| `0x00427260` | `void __thiscall BuildRectFromControlDimensions_Impl(TControl * this)` |
| `0x00427290` | `void __thiscall BuildRectFromControlPositionAndSizeFields(TControl * this, int * pOutRect)` |
| `0x004272d0` | `void __thiscall DispatchVslot134WithRectAndRectPlus8_Impl(TControl * this)` |
| `0x00485e90` | `void __thiscall HandleTurnEventVtableSlot08ConditionalDispatch(TControl * this, int arg1)` |
| `0x0048a260` | `void __thiscall SetCityDialogFlagByte4(TControl * this, char flagValue)` |
| `0x0048a2e0` | `void __thiscall DispatchUiCommandToHandler(TControl * this, int commandId, void * eventArg, int eventExtra)` |
| `0x0048a310` | `void __thiscall ForwardNotifyParamToPrimaryChildSlot44(TControl * this, int notifyValue)` |
| `0x0048a380` | `void __thiscall ForwardCityDialogParamToChildSlot48(TControl * this)` |
| `0x0048a3b0` | `void __thiscall DispatchQueuedUiCommandAndRelease(TControl * this)` |
| `0x0048a3f0` | `void __thiscall DispatchUiSelectionToHandler(TControl * this)` |
| `0x0048a4a0` | `void __thiscall DetachActiveCityProductionChildIfMatches(TControl * this)` |
| `0x0048a4d0` | `void __thiscall SetUiResourceOwner(TControl * this, TControl * pOwner)` |
| `0x0048a670` | `void __thiscall DispatchCityProductionAction1A(TControl * this)` |
| `0x0048a690` | `void __thiscall HandleCityDialogNoOpA(TControl * this, int activeFlag, int refreshNow)` |
| `0x0048a6b0` | `void __thiscall NoOpUiSetControlVisibleFlag(TControl * this, int visibleFlag)` |
| `0x0048a6d0` | `void __thiscall DispatchUiCommand19ToParent(TControl * this)` |
| `0x0048aaf0` | `void __thiscall DispatchControlEventToChildrenAndSelf(TControl * this, int eventArg)` |
| `0x0048ab90` | `void __thiscall ForwardMapViewVirtualC4IfPresent(TControl * this, int arg2)` |
| `0x0048abc0` | `void __thiscall NoOpUiCallback(TControl * this)` |
| `0x0048abe0` | `void __thiscall RunNationInfoModalAndReturnNonCancel_Impl(TControl * this)` |
| `0x0048ae60` | `void __thiscall DetachUiElementFromOwnerListAndClearBackref(TControl * this, TControl * pUiElement)` |
| `0x0048afd0` | `void * __thiscall FindUiChildControlByWindowHandleRecursive(TControl * this, int windowHandle)` |
| `0x0048b070` | `void __thiscall SetUiControlVisibleFlagAndMaybeRefreshWindow(TControl * this, int visibleFlag)` |
| `0x0048b0b0` | `void __thiscall CloseCityDialogChildrenAndReleaseSelf(TControl * this)` |
| `0x0048b180` | `int __thiscall GetCityDialogValueViaChildSlot58(TControl * this)` |
| `0x0048b1a0` | `int __thiscall QueryChildMapViewSlot58OrZero(TControl * this)` |
| `0x0048b1c0` | `void __thiscall SetControlActiveFlagAndRefreshIfChanged(TControl * this, int activeFlag, int refreshIfChanged)` |
| `0x0048b200` | `bool __thiscall CanProcessMapViewSlotECUnderWindowState(TControl * this)` |
| `0x0048b250` | `void __thiscall WrapperFor_InvalidateCityDialogRectRegion_At0048b250(TControl * this, int arg1, int arg2)` |
| `0x0048b2d0` | `void __thiscall WrapperFor_thunk_PopSinglyLinkedListHeadPointer_At0048b2d0(TControl * this)` |
| `0x0048b3f0` | `void __thiscall UpdateControlPositionAndInvalidateUnionRect(TControl * this, int arg1, int arg2)` |
| `0x0048b4b0` | `void __thiscall InvalidateOffsetRegionUsingChildClipRect(TControl * this, int * clipState)` |
| `0x0048b690` | `void __thiscall ValidateControlRectIfWindowActive(TControl * this, int * pRect)` |
| `0x0048b6d0` | `void __thiscall WrapperFor_thunk_InvalidateCityDialogRectRegion_At0048b6d0(TControl * this)` |
| `0x0048b700` | `void __thiscall ResetUiInputCaptureState(TControl * this)` |
| `0x0048b770` | `bool __thiscall SetGlobalUiSelectionIfChangedAndNotify(TControl * this)` |
| `0x0048b7b0` | `bool __thiscall WrapperFor_GetOrCreateHandleMapObjectByHandle_At0048b7b0(TControl * this, void * pExistingHandleMap)` |
| `0x0048b810` | `void __thiscall WrapperFor_AllocateWithFallbackHandler_At0048b810(TControl * this)` |
| `0x0048b8d0` | `void __thiscall PaintVisibleChildrenIntersectingClipRect(TControl * this)` |
| `0x0048ba40` | `void __thiscall OffsetRectByControlPositionAndDispatchVslot138_Impl(TControl * this)` |
| `0x0048ba80` | `void __thiscall OffsetRectByControlPositionAndDispatchVslot138_EcxBridge_Impl(TControl * this, int * pRect)` |
| `0x0048bb00` | `void __thiscall OffsetRectByControlPosition_Impl(TControl * this, int * pRect)` |
| `0x0048c000` | `bool __thiscall EvaluateControlInputGate(TControl * this)` |
| `0x0048c050` | `bool __thiscall HasRenderableParentAndContent(TControl * this)` |
| `0x0048c080` | `void __thiscall HandleCursorHoverSelectionByChildHitTestAndFallback(TControl * this, int arg1, int arg2)` |
| `0x0048c1e0` | `void __thiscall RefreshCityProductionViewStateFromContext(TControl * this)` |
| `0x0048c380` | `void __thiscall UpdateRectCacheIfChangedAndInvalidateCityDialog(TControl * this, int arg1, int arg2)` |
| `0x0048c450` | `void __thiscall DispatchUiMouseMoveToChildren(TControl * this, int arg1, int arg2, int arg3, int arg4)` |
| `0x0048c590` | `int __thiscall DispatchUiMouseEventToChildrenOrSelf_Impl(TControl * this, int param3, int param4, int param5, int param_4)` |
| `0x0048c750` | `void __thiscall DrawRectangleInCurrentUiContext(TControl * this, int * pRect)` |
| `0x0048c7a0` | `void __thiscall AssertMcAppUILine1914(TControl * this)` |
| `0x0048c7d0` | `void __thiscall AssertMcAppUILine1922(TControl * this)` |
| `0x0048c890` | `void __thiscall DispatchVfuncA0ToLinkedChildListSlot44(TControl * this)` |
| `0x0048e520` | `void __thiscall ConstructUiCommandTagResourceEntryBase(TControl * this)` |
| `0x0048e590` | `TControl * __thiscall DestructTControlAndMaybeFree(TControl * this, byte freeSelfFlag)` |
| `0x0048e640` | `void __thiscall BeginMouseCaptureAndStartRepeatTimer(TControl * this, int arg1, int arg2, int arg3, int arg4)` |
| `0x0048e7a0` | `void __thiscall SetControlPictureEntryAndMaybeRefresh(TControl * this, int * pPictureEntryRef, bool fRefreshNow)` |
| `0x0048e7d0` | `void __thiscall SetCityProductionDialogPictureRectAndMaybeRefresh(TControl * this, int * pRectState, int refreshFlag)` |
| `0x0048e810` | `void __thiscall SetControlStateFlagAndMaybeRefresh(TControl * this, bool fEnabledState, bool fRefreshNow)` |
| `0x0048e850` | `void __thiscall DispatchPictureResourceCommand(TControl * this, int nEventType, void * pEventSender, void * pEventDataA, PanelEventPayload * pEventDataB)` |
| `0x0048e980` | `void __thiscall WrapperFor_ApplyRectMarginsInPlace_At0048e980(TControl * this)` |
| `0x0048e9c0` | `void __thiscall NoOpUiViewSlotHandler(TControl * this)` |
| `0x00492e10` | `void __cdecl DestructTControlAndMaybeFree_Impl(void)` |

- TControl thunk mirrors: `69` (kept in source CSV)

### TradeControl primary (`22`)
| Address | Signature |
|---|---|
| `0x00412bf0` | `void __cdecl NoOpTurnEventStateVtableSlot0C(void)` |
| `0x00412c10` | `void __cdecl NoOpTurnEventStateVtableSlot10(void)` |
| `0x00415ce0` | `void __cdecl HandleTurnEventVtableSlot24CopyPayloadBuffer(void)` |
| `0x00415d50` | `int __fastcall GetCityDialogValueDword10(CityDialogController * pDialog)` |
| `0x00427240` | `void __cdecl NoOpControlCallback_Impl(void)` |
| `0x00429450` | `void __cdecl GetCityProductionControllerField60(void)` |
| `0x00429470` | `void __cdecl AssertCityProductionGlobalStateInitialized(void)` |
| `0x004294a0` | `bool __cdecl LogUnhandledDialogMethodAndReturnFalse(void)` |
| `0x00485f70` | `void __cdecl HandleCityDialogNoOpSlot14(void)` |
| `0x00485f90` | `void __cdecl HandleCityDialogNoOpSlot18(void)` |
| `0x0048a240` | `byte __fastcall GetCityDialogFlagByte4(CityDialogController * pDialog)` |
| `0x0048a2c0` | `int __fastcall GetCityDialogValueDwordC(CityDialogController * pDialog)` |
| `0x0048a480` | `void __cdecl CanHandleCityDialogActionFalse(void)` |
| `0x0048a500` | `void __cdecl IsCurrentActiveCityProductionView(void)` |
| `0x0048a530` | `void __cdecl CanStartCityProductionActionFalse(void)` |
| `0x0048a550` | `void __cdecl GetCityDialogZeroValue(void)` |
| `0x0048a570` | `void __cdecl ActivateCityProductionViewIfAllowed(void)` |
| `0x0048a650` | `void __cdecl HandleCityProductionNoOp(void)` |
| `0x0048a6f0` | `void __cdecl DispatchCityProductionAction1B(void)` |
| `0x0048b860` | `void __cdecl WrapperFor_InvalidateCityDialogRectRegion_At0048b860(void)` |
| `0x0048c250` | `void __cdecl UpdateMapCursorFromSelectionContext(void)` |
| `0x0048e9e0` | `void __cdecl NoOpCityProductionDialogPictureHook(void)` |

- TradeControl thunk mirrors: `22` (kept in source CSV)

## VTable Slot Map
| Slot | Offset | Interface Method | Consensus Target | Distinct Targets |
|---|---|---|---|---|
| `0` | `0x0000` | `CtrlSlot00` | `mixed (10); dominant=thunk_GetTAmtBarClassNamePointer@0x00405afb (1/10)` | `10` |
| `1` | `0x0004` | `CtrlSlot01` | `mixed (10); dominant=thunk_DestructTAmtBarAndMaybeFree@0x00407b17 (1/10)` | `10` |
| `2` | `0x0008` | `CtrlSlot02` | `thunk_HandleTurnEventVtableSlot08ConditionalDispatch@0x00407c57` | `1` |
| `3` | `0x000c` | `CtrlSlot03` | `thunk_NoOpTurnEventStateVtableSlot0C@0x004010a0` | `1` |
| `4` | `0x0010` | `CtrlSlot04` | `thunk_NoOpTurnEventStateVtableSlot10@0x00408625` | `1` |
| `5` | `0x0014` | `CtrlSlot05` | `thunk_HandleCityDialogNoOpSlot14@0x0040583a` | `1` |
| `6` | `0x0018` | `CtrlSlot06` | `thunk_HandleCityDialogNoOpSlot18@0x00403517` | `1` |
| `7` | `0x001c` | `CtrlSlot07` | `thunk_CloseCityDialogChildrenAndReleaseSelf@0x00408db4` | `1` |
| `8` | `0x0020` | `CtrlSlot08` | `mixed (3); dominant=thunk_CloneEngineerDialogStateToNewInstance@0x004082ce (6/10)` | `3` |
| `9` | `0x0024` | `CtrlSlot09` | `thunk_HandleTurnEventVtableSlot24CopyPayloadBuffer@0x00405c59` | `1` |
| `10` | `0x0028` | `CtrlSlot10` | `thunk_GetCityDialogFlagByte4@0x00404cfa` | `1` |
| `11` | `0x002c` | `SetControlValueSlot2C` | `thunk_SetCityDialogFlagByte4@0x0040739c` | `1` |
| `12` | `0x0030` | `QueryStepValueSlot30` | `thunk_GetCityDialogValueDwordC@0x00404d9f` | `1` |
| `13` | `0x0034` | `CtrlSlot13` | `thunk_DispatchQueuedUiCommandAndRelease@0x0040740a` | `1` |
| `14` | `0x0038` | `CtrlSlot14` | `thunk_DispatchUiSelectionToHandler@0x00406a91` | `1` |
| `15` | `0x003c` | `CtrlSlot15` | `mixed (4); dominant=thunk_ForwardEngineerDialogCommandToChildSlot40@0x00408657 (6/10)` | `4` |
| `16` | `0x0040` | `CtrlSlot16` | `thunk_DispatchUiCommandToHandler@0x004041a6` | `1` |
| `17` | `0x0044` | `CtrlSlot17` | `thunk_ForwardNotifyParamToPrimaryChildSlot44@0x004069ec` | `1` |
| `18` | `0x0048` | `CtrlSlot18` | `thunk_ForwardCityDialogParamToChildSlot48@0x00401d61` | `1` |
| `19` | `0x004c` | `CtrlSlot19` | `thunk_CanHandleCityDialogActionFalse@0x004092c8` | `1` |
| `20` | `0x0050` | `CtrlSlot20` | `thunk_GetCityDialogValueDword10@0x00405d85` | `1` |
| `21` | `0x0054` | `CtrlSlot21` | `thunk_SetCityDialogValueDword10@0x004090d4` | `1` |
| `22` | `0x0058` | `CtrlSlot22` | `thunk_GetCityDialogValueViaChildSlot58@0x00407c16` | `1` |
| `23` | `0x005c` | `CtrlSlot23` | `thunk_CanStartCityProductionActionFalse@0x00403a94` | `1` |
| `24` | `0x0060` | `CtrlSlot24` | `thunk_GetCityDialogZeroValue@0x004056e1` | `1` |
| `25` | `0x0064` | `CtrlSlot25` | `thunk_NoOpUiSetControlActiveFlag@0x004088c8` | `1` |
| `26` | `0x0068` | `CtrlSlot26` | `thunk_NoOpUiSetControlVisibleFlag@0x004097f5` | `1` |
| `27` | `0x006c` | `CtrlSlot27` | `thunk_HandleCityProductionNoOp@0x00401834` | `1` |
| `28` | `0x0070` | `CtrlSlot28` | `thunk_DispatchUiCommand19ToParent@0x004096d3` | `1` |
| `29` | `0x0074` | `CtrlSlot29` | `thunk_DispatchCityProductionAction1A@0x00403a03` | `1` |
| `30` | `0x0078` | `CtrlSlot30` | `thunk_DispatchCityProductionAction1B@0x00404fcf` | `1` |
| `31` | `0x007c` | `CtrlSlot31` | `thunk_ActivateCityProductionViewIfAllowed@0x00401e1f` | `1` |
| `32` | `0x0080` | `CtrlSlot32` | `<none>` | `0` |
| `33` | `0x0084` | `CtrlSlot33` | `<none>` | `0` |
| `34` | `0x0088` | `CtrlSlot34` | `thunk_IsCurrentActiveCityProductionView@0x00405f9c` | `1` |
| `35` | `0x008c` | `CtrlSlot35` | `thunk_DetachActiveCityProductionChildIfMatches@0x004042af` | `1` |
| `36` | `0x0090` | `CtrlSlot36` | `thunk_SetUiResourceOwner@0x004093d1` | `1` |
| `37` | `0x0094` | `CtrlSlot37` | `thunk_FindUiChildControlByWindowHandleRecursive@0x0040424b` | `1` |
| `38` | `0x0098` | `CtrlSlot38` | `<none>` | `0` |
| `39` | `0x009c` | `CtrlSlot39` | `<none>` | `0` |
| `40` | `0x00a0` | `CtrlSlot40` | `thunk_DispatchVfuncA0ToLinkedChildListSlot44@0x00409a8e` | `1` |
| `41` | `0x00a4` | `SetEnabledSlotA4` | `thunk_SetControlActiveFlagAndRefreshIfChanged@0x00404e21` | `1` |
| `42` | `0x00a8` | `SetStateSlotA8` | `thunk_SetUiControlVisibleFlagAndMaybeRefreshWindow@0x004026cb` | `1` |
| `43` | `0x00ac` | `CtrlSlot43` | `<none>` | `0` |
| `44` | `0x00b0` | `CtrlSlot44` | `thunk_UpdateMapCursorFromSelectionContext@0x00401226` | `1` |
| `45` | `0x00b4` | `CtrlSlot45` | `<none>` | `0` |
| `46` | `0x00b8` | `CtrlSlot46` | `thunk_RefreshCityProductionViewStateFromContext@0x00401267` | `1` |
| `47` | `0x00bc` | `CtrlSlot47` | `mixed (2); dominant=thunk_ReturnZeroStatus@0x00404818 (6/10)` | `2` |
| `48` | `0x00c0` | `CtrlSlot48` | `thunk_InvalidateOffsetRegionUsingChildClipRect@0x004088b4` | `1` |
| `49` | `0x00c4` | `CtrlSlot49` | `thunk_ForwardMapViewVirtualC4IfPresent@0x00405b82` | `1` |
| `50` | `0x00c8` | `CtrlSlot50` | `thunk_ValidateControlRectIfWindowActive@0x00406014` | `1` |
| `51` | `0x00cc` | `CtrlSlot51` | `thunk_EvaluateControlInputGate@0x004053c6` | `1` |
| `52` | `0x00d0` | `CtrlSlot52` | `thunk_HasRenderableParentAndContent@0x0040993a` | `1` |
| `53` | `0x00d4` | `CtrlSlot53` | `thunk_HandleCursorHoverSelectionByChildHitTestAndFallback@0x00408b07` | `1` |
| `54` | `0x00d8` | `CtrlSlot54` | `thunk_DispatchControlEventToChildrenAndSelf@0x004046d3` | `1` |
| `55` | `0x00dc` | `CtrlSlot55` | `mixed (7); dominant=thunk_NoOpUiLifecycleHook@0x00406ba9 (3/10)` | `7` |
| `56` | `0x00e0` | `CtrlSlot56` | `thunk_NoOpUiCallback@0x00408274` | `1` |
| `57` | `0x00e4` | `CtrlSlot57` | `thunk_WrapperFor_InvalidateCityDialogRectRegion_At0048b6d0@0x00406604` | `1` |
| `58` | `0x00e8` | `CtrlSlot58` | `thunk_QueryChildMapViewSlot58OrZero@0x00404de0` | `1` |
| `59` | `0x00ec` | `IsActionableSlotEC` | `thunk_CanProcessMapViewSlotECUnderWindowState@0x00408350` | `1` |
| `60` | `0x00f0` | `CaptureLayoutSlotF0` | `thunk_WrapperFor_InvalidateCityDialogRectRegion_At0048b250@0x00404e3a` | `1` |
| `61` | `0x00f4` | `CaptureLayoutSlotF4` | `thunk_UpdateControlPositionAndInvalidateUnionRect@0x00403eef` | `1` |
| `62` | `0x00f8` | `RefreshSlotF8` | `thunk_SetGlobalUiSelectionIfChangedAndNotify@0x00405916` | `1` |
| `63` | `0x00fc` | `CtrlSlot63` | `thunk_NoOpCommandHandler@0x00403a85` | `1` |
| `64` | `0x0100` | `CtrlSlot64` | `thunk_WrapperFor_GetOrCreateHandleMapObjectByHandle_At0048b7b0@0x004015ff` | `1` |
| `65` | `0x0104` | `CtrlSlot65` | `<none>` | `0` |
| `66` | `0x0108` | `CtrlSlot66` | `thunk_WrapperFor_AllocateWithFallbackHandler_At0048b810@0x00401451` | `1` |
| `67` | `0x010c` | `CtrlSlot67` | `thunk_PaintVisibleChildrenIntersectingClipRect@0x00406ef1` | `1` |
| `68` | `0x0110` | `CtrlSlot68` | `mixed (4); dominant=thunk_InvokeSlot1A8NoArg@0x00405cc7 (5/10)` | `4` |
| `69` | `0x0114` | `UpdateAfterBitmapChangeSlot114` | `thunk_WrapperFor_InvalidateCityDialogRectRegion_At0048b860@0x00402b8a` | `1` |
| `70` | `0x0118` | `CtrlSlot70` | `thunk_DispatchUiMouseMoveToChildren@0x0040723e` | `1` |
| `71` | `0x011c` | `CtrlSlot71` | `mixed (2); dominant=thunk_ClampAndApplyTradeMoveValue@0x00402df6 (5/10)` | `2` |
| `72` | `0x0120` | `CtrlSlot72` | `DispatchUiMouseEventToChildrenOrSelf@0x00406429` | `1` |
| `73` | `0x0124` | `CtrlSlot73` | `thunk_NoOpControlCallback_Impl@0x004093e5` | `1` |
| `74` | `0x0128` | `CtrlSlot74` | `thunk_BuildRectFromControlDimensions_Impl@0x00404b7e` | `1` |
| `75` | `0x012c` | `QueryBoundsSlot12C` | `thunk_BuildRectFromControlPositionAndSizeFields@0x004067da` | `1` |
| `76` | `0x0130` | `CtrlSlot76` | `thunk_DispatchVslot134WithRectAndRectPlus8_Impl@0x00405c7c` | `1` |
| `77` | `0x0134` | `CtrlSlot77` | `thunk_OffsetRectByControlPositionAndDispatchVslot138_EcxBridge_Impl@0x00406578` | `1` |
| `78` | `0x0138` | `CtrlSlot78` | `thunk_OffsetRectByControlPositionAndDispatchVslot138_Impl@0x00402d4c` | `1` |
| `79` | `0x013c` | `CtrlSlot79` | `thunk_ResetUiInputCaptureState@0x00408a5d` | `1` |
| `80` | `0x0140` | `CtrlSlot80` | `thunk_OffsetRectByControlPosition_Impl@0x00402bf3` | `1` |
| `81` | `0x0144` | `CtrlSlot81` | `<none>` | `0` |
| `82` | `0x0148` | `CtrlSlot82` | `<none>` | `0` |
| `83` | `0x014c` | `CtrlSlot83` | `<none>` | `0` |
| `84` | `0x0150` | `CtrlSlot84` | `<none>` | `0` |
| `85` | `0x0154` | `CtrlSlot85` | `<none>` | `0` |
| `86` | `0x0158` | `CtrlSlot86` | `<none>` | `0` |
| `87` | `0x015c` | `CtrlSlot87` | `<none>` | `0` |
| `88` | `0x0160` | `CtrlSlot88` | `<none>` | `0` |

## Header Skeleton
```cpp
// Layout contract only; keep unresolved slots/methods as-is until stronger evidence.
struct TControl;
struct TradeControl;

struct TradeControl {
    void* pVtable;
    // +0x04: uint cityDialogFlag4;
    // +0x08: uint controlActiveFlag8;
    // +0x0c: uint dialogValueDwordC;
    // +0x10: uint dialogValueDword10;
    // +0x18: void * pUiOwner18;
    // +0x1c: uint controlTag;
    // +0x20: void * pChildMapView20;
    // +0x24: uint controlPosX24;
    // +0x28: uint controlPosY28;
    // +0x2c: uint cachedPosX2c;
    // +0x30: uint cachedPosY30;
    // +0x34: uint controlWidth34;
    // +0x38: uint controlHeight38;
    // +0x44: void * pChildControlList44;
    // +0x4c: byte inputEnableFlag4c;
    // +0x4d: byte renderEnableFlag4d;
    // +0x50: void * pWindowOwner50;
    // +0x5c: uint inputGateOverride5c;
    // +0x60: ushort barValue60;
    // +0x62: ushort barSelected62;
    // +0x64: ushort barLimit64;
    // +0x66: ushort barAux66;
    // +0x84: ushort bitmapId;
    // +0x94: uint autoRepeatTick94;
};
```

