# TView/TControl VTable Contract

## Sources
- matrix: `tmp_decomp/batch751_tview_tcontrol_trade_vtbl_apply_matrix.csv`
- base class: `TView`
- mid class: `TControl`
- derived classes: `TAmtBar, TIndustryAmtBar, TRailAmtBar, TShipAmtBar, TTraderAmtBar, THQButton, TArmyPlacard, TPlacard`

## Summary
- slots scanned: `125`
- `TControl` overrides vs `TView`: `7`
- derived override slots vs `TControl`: `18`
- base max resolved slot: `103`
- mid max resolved slot: `112`
- non-gap extension/abstract slots: `21`
- potential unresolved base/mid slots: `0`

## TControl Overrides vs TView
| Slot | Offset | Interface Method | Base Target | Mid Target |
|---|---|---|---|---|
| `0` | `0x0000` | `CtrlSlot00` | `thunk_GetTViewClassNamePointer@0x00401096` | `thunk_GetTControlClassNamePointer@0x00401537` |
| `1` | `0x0004` | `CtrlSlot01` | `thunk_DestructTViewAndMaybeFree@0x00404318` | `thunk_DestructTControlAndMaybeFree@0x00407801` |
| `8` | `0x0020` | `CtrlSlot08` | `thunk_CloneEngineerDialogStateToNewInstance@0x004082ce` | `thunk_WrapperFor_thunk_TemporarilyClearAndRestoreUiInvalidationFlag_At00435760@0x00408e0e` |
| `15` | `0x003c` | `CtrlSlot15` | `thunk_ForwardEngineerDialogCommandToChildSlot40@0x00408657` | `thunk_HandleCityDialogToggleCommandOrForward@0x00404566` |
| `47` | `0x00bc` | `CtrlSlot47` | `thunk_ReturnZeroStatus@0x00404818` | `thunk_GetCityProductionControllerField60@0x00406951` |
| `71` | `0x011c` | `CtrlSlot71` | `thunk_OrphanRetStub_00430c10_At00402e28@0x00402e28` | `thunk_BeginMouseCaptureAndStartRepeatTimer@0x0040750e` |
| `91` | `0x016c` | `CtrlSlot91` | `thunk_OrphanCallChain_C3_I32_0048c6d0_At00402c20@0x00402c20` | `thunk_CtrlSlot91_PtInRectWithBoundsFromSlot128_Impl@0x00409034` |

## Derived Overrides vs TControl
| Slot | Offset | Interface Method | Mid Target | Derived Overrides |
|---|---|---|---|---|
| `0` | `0x0000` | `CtrlSlot00` | `thunk_GetTControlClassNamePointer@0x00401537` | `TAmtBar:thunk_GetTAmtBarClassNamePointer@0x00405afb; TIndustryAmtBar:thunk_GetTIndustryAmtBarClassNamePointer@0x004022a7; TRailAmtBar:thunk_GetTRailAmtBarClassNamePointer@0x00403ee0; TShipAmtBar:thunk_GetTShipAmtBarClassNamePointer@0x00409737; TTraderAmtBar:thunk_GetLiteralTypeName_TTraderAmtBar@0x00408fe4; THQButton:thunk_GetTHQButtonClassNamePointer@0x00404d86; TArmyPlacard:thunk_GetTArmyPlacardClassNamePointer@0x00406564; TPlacard:thunk_GetTPlacardClassNamePointer@0x00402d5b` |
| `1` | `0x0004` | `CtrlSlot01` | `thunk_DestructTControlAndMaybeFree@0x00407801` | `TAmtBar:thunk_DestructTAmtBarAndMaybeFree@0x00407b17; TIndustryAmtBar:thunk_DestructTIndustryAmtBarAndMaybeFree@0x004051eb; TRailAmtBar:thunk_DestructTRailAmtBarAndMaybeFree@0x00407176; TShipAmtBar:thunk_DestructTShipAmtBarAndMaybeFree@0x00402eaa; TTraderAmtBar:thunk_DestructTTraderAmtBarMaybeFree@0x00404647; THQButton:thunk_DestructTHQButtonAndMaybeFree@0x00407d88; TArmyPlacard:thunk_DestructTArmyPlacardAndMaybeFree@0x0040957f; TPlacard:thunk_DestructTPlacardAndMaybeFree@0x0040399a` |
| `8` | `0x0020` | `CtrlSlot08` | `thunk_WrapperFor_thunk_TemporarilyClearAndRestoreUiInvalidationFlag_At00435760@0x00408e0e` | `TAmtBar:thunk_CloneEngineerDialogStateToNewInstance@0x004082ce; TIndustryAmtBar:thunk_CloneEngineerDialogStateToNewInstance@0x004082ce; TRailAmtBar:thunk_CloneEngineerDialogStateToNewInstance@0x004082ce; TShipAmtBar:thunk_CloneEngineerDialogStateToNewInstance@0x004082ce; TTraderAmtBar:thunk_CloneEngineerDialogStateToNewInstance@0x004082ce; THQButton:thunk_CloneCityDialogExtendedStateToNewInstance@0x0040844f; TArmyPlacard:thunk_CloneCityDialogExtendedStateToNewInstance@0x0040844f; TPlacard:thunk_CloneCityDialogExtendedStateToNewInstance@0x0040844f` |
| `15` | `0x003c` | `CtrlSlot15` | `thunk_HandleCityDialogToggleCommandOrForward@0x00404566` | `TAmtBar:thunk_ForwardEngineerDialogCommandToChildSlot40@0x00408657; TIndustryAmtBar:thunk_ForwardEngineerDialogCommandToChildSlot40@0x00408657; TRailAmtBar:thunk_ForwardEngineerDialogCommandToChildSlot40@0x00408657; TShipAmtBar:thunk_ForwardEngineerDialogCommandToChildSlot40@0x00408657; TTraderAmtBar:thunk_ForwardEngineerDialogCommandToChildSlot40@0x00408657; THQButton:thunk_WrapperFor_HandleCityDialogToggleCommandOrForward_At0058b7f0@0x0040157d; TArmyPlacard:thunk_HandlePlusMinusCommandAndInvokeVslot1CC@0x00406550` |
| `47` | `0x00bc` | `CtrlSlot47` | `thunk_GetCityProductionControllerField60@0x00406951` | `TAmtBar:thunk_ReturnZeroStatus@0x00404818; TIndustryAmtBar:thunk_ReturnZeroStatus@0x00404818; TRailAmtBar:thunk_ReturnZeroStatus@0x00404818; TShipAmtBar:thunk_ReturnZeroStatus@0x00404818; TTraderAmtBar:thunk_ReturnZeroStatus@0x00404818` |
| `55` | `0x00dc` | `CtrlSlot55` | `thunk_NoOpUiLifecycleHook@0x00406ba9` | `TAmtBar:thunk_WrapperFor_thunk_NoOpUiLifecycleHook_At00588610_At00407d8d@0x00407d8d; TIndustryAmtBar:thunk_InitializeTradeBarsFromSelectedCommodityControl@0x004036e3; TRailAmtBar:thunk_SelectTradeSummaryMetricByTagAndUpdateBarValues@0x00402cf7; TShipAmtBar:thunk_SelectTradeSpecialCommodityAndRecomputeBarLimits@0x00408b7a; TTraderAmtBar:thunk_UpdateNationStateGaugeValuesFromScenarioRecordCode@0x004043c2; THQButton:thunk_WrapperFor_thunk_NoOpUiLifecycleHook_At0058b6e0_At0040179e@0x0040179e` |
| `68` | `0x0110` | `CtrlSlot68` | `thunk_OrphanRetStub_00430bf0_At0040757c@0x0040757c` | `TAmtBar:thunk_InvokeSlot1A8NoArg@0x00405cc7; TIndustryAmtBar:thunk_InvokeSlot1A8NoArg@0x00405cc7; TRailAmtBar:thunk_InvokeSlot1A8NoArg@0x00405cc7; TShipAmtBar:thunk_InvokeSlot1A8NoArg@0x00405cc7; TTraderAmtBar:thunk_InvokeSlot1A8NoArg@0x00405cc7; THQButton:thunk_RenderHintHelperWithCtrlModifierOverlay@0x00404fe8; TArmyPlacard:thunk_RenderRightAlignedNumericOverlayWithShadow_At0040178f@0x0040178f; TPlacard:thunk_RenderPlacardValueTextWithShadow@0x00404cb9` |
| `71` | `0x011c` | `CtrlSlot71` | `thunk_BeginMouseCaptureAndStartRepeatTimer@0x0040750e` | `TAmtBar:thunk_ClampAndApplyTradeMoveValue@0x00402df6; TIndustryAmtBar:thunk_ClampAndApplyTradeMoveValue@0x00402df6; TRailAmtBar:thunk_ClampAndApplyTradeMoveValue@0x00402df6; TShipAmtBar:thunk_ClampAndApplyTradeMoveValue@0x00402df6; TTraderAmtBar:thunk_ClampAndApplyTradeMoveValue@0x00402df6` |
| `91` | `0x016c` | `CtrlSlot91` | `thunk_CtrlSlot91_PtInRectWithBoundsFromSlot128_Impl@0x00409034` | `TAmtBar:thunk_OrphanCallChain_C3_I32_0048c6d0_At00402c20@0x00402c20; TIndustryAmtBar:thunk_OrphanCallChain_C3_I32_0048c6d0_At00402c20@0x00402c20; TRailAmtBar:thunk_OrphanCallChain_C3_I32_0048c6d0_At00402c20@0x00402c20; TShipAmtBar:thunk_OrphanCallChain_C3_I32_0048c6d0_At00402c20@0x00402c20; TTraderAmtBar:thunk_OrphanCallChain_C3_I32_0048c6d0_At00402c20@0x00402c20` |
| `104` | `0x01a0` | `ApplyMoveClampSlot1A0` | `thunk_DispatchPictureResourceCommand@0x00407978` | `TAmtBar:thunk_OrphanLeaf_NoCall_Ins02_00586e50@0x00406fbe; TIndustryAmtBar:thunk_OrphanLeaf_NoCall_Ins02_00586e50@0x00406fbe; TRailAmtBar:thunk_OrphanLeaf_NoCall_Ins02_00586e50@0x00406fbe; TShipAmtBar:thunk_OrphanLeaf_NoCall_Ins02_00586e50@0x00406fbe; TTraderAmtBar:thunk_WrapperFor_GetActiveNationId_At0058b070@0x004040fc` |
| `105` | `0x01a4` | `SetBarMetricSlot1A4` | `thunk_WrapperFor_ApplyRectMarginsInPlace_At0048e980@0x00405579` | `TAmtBar:thunk_UpdateBarValuesAndRefresh@0x00403823; TIndustryAmtBar:thunk_UpdateBarValuesAndRefresh@0x00403823; TRailAmtBar:thunk_UpdateBarValuesAndRefresh@0x00403823; TShipAmtBar:thunk_UpdateBarValuesAndRefresh@0x00403823; TTraderAmtBar:thunk_UpdateBarValuesAndRefresh@0x00403823` |
| `106` | `0x01a8` | `CtrlSlot106` | `thunk_AssertCityProductionGlobalStateInitialized@0x00401e2e` | `TAmtBar:thunk_RenderPrimarySurfaceOverlayPanelWithClipCache_At004038c8@0x004038c8; TIndustryAmtBar:thunk_RenderQuickDrawControlWithHitRegionClipVariantA@0x00408562; TRailAmtBar:thunk_RenderQuickDrawControlWithHitRegionClipVariantB@0x00408b43; TShipAmtBar:thunk_RenderQuickDrawControlWithHitRegionClipVariantC@0x00403ffd; TTraderAmtBar:thunk_RenderControlWithTemporaryRectClipRegionAndChildren@0x00405975` |
| `107` | `0x01ac` | `SetBarMetricRatioSlot1AC` | `thunk_NoOpUiViewSlotHandler@0x00406eb5` | `TIndustryAmtBar:thunk_RenderQuickDrawOverlayWithHitRegionVariantA@0x00408431; TRailAmtBar:thunk_RenderQuickDrawOverlayWithHitRegionVariantB@0x00402478` |
| `112` | `0x01c0` | `CtrlSlot112` | `thunk_SetControlStateFlagAndMaybeRefresh@0x0040516e` | `THQButton:thunk_OrphanCallChain_C3_I43_0058b750_At0040415b@0x0040415b` |
| `113` | `0x01c4` | `SetStyleStateSlot1C4` | `<none>` | `THQButton:thunk_ResetPictureResourceEntry@0x0040421e (mid=<none>); TArmyPlacard:thunk_ResetPictureResourceEntry@0x0040421e (mid=<none>); TPlacard:thunk_ResetPictureResourceEntry@0x0040421e (mid=<none>)` |
| `114` | `0x01c8` | `SetBitmapSlot1C8` | `<none>` | `THQButton:thunk_SetPictureResourceIdAndRefresh@0x00408454 (mid=<none>); TArmyPlacard:thunk_SetPictureResourceIdAndRefresh@0x00408454 (mid=<none>); TPlacard:thunk_SetPictureResourceIdAndRefresh@0x00408454 (mid=<none>)` |
| `115` | `0x01cc` | `InvokeSlot1CCVirtual` | `<none>` | `THQButton:thunk_InvokeSlot1CCIfSlot28Enabled@0x00406028 (mid=<none>); TArmyPlacard:thunk_WrapperFor_GetActiveNationId_At0058bf50@0x004040c5 (mid=<none>); TPlacard:thunk_WrapperFor_thunk_InvalidateCityDialogRectRegion_At0058bb50@0x0040380a (mid=<none>)` |
| `116` | `0x01d0` | `CtrlSlot116` | `<none>` | `THQButton:thunk_OrphanCallChain_C2_I37_0058b8d0_At00408891@0x00408891 (mid=<none>)` |

## Non-gap Slot Classes (Intentional Base/Mid Absence)
| Slot | Offset | Interface Method | Classification | Base Target | Mid Target | Derived Present |
|---|---|---|---|---|---|---|
| `104` | `0x01a0` | `ApplyMoveClampSlot1A0` | `mid_or_derived_extension` | `<none>` | `thunk_DispatchPictureResourceCommand@0x00407978` | `TAmtBar, TIndustryAmtBar, TRailAmtBar, TShipAmtBar, TTraderAmtBar, THQButton, TArmyPlacard, TPlacard` |
| `105` | `0x01a4` | `SetBarMetricSlot1A4` | `mid_or_derived_extension` | `<none>` | `thunk_WrapperFor_ApplyRectMarginsInPlace_At0048e980@0x00405579` | `TAmtBar, TIndustryAmtBar, TRailAmtBar, TShipAmtBar, TTraderAmtBar, THQButton, TArmyPlacard, TPlacard` |
| `106` | `0x01a8` | `CtrlSlot106` | `mid_or_derived_extension` | `<none>` | `thunk_AssertCityProductionGlobalStateInitialized@0x00401e2e` | `TAmtBar, TIndustryAmtBar, TRailAmtBar, TShipAmtBar, TTraderAmtBar, THQButton, TArmyPlacard, TPlacard` |
| `107` | `0x01ac` | `SetBarMetricRatioSlot1AC` | `mid_or_derived_extension` | `<none>` | `thunk_NoOpUiViewSlotHandler@0x00406eb5` | `TIndustryAmtBar, TRailAmtBar, THQButton, TArmyPlacard, TPlacard` |
| `108` | `0x01b0` | `CtrlSlot108` | `mid_or_derived_extension` | `<none>` | `thunk_NoOpCityProductionDialogPictureHook@0x004068d4` | `THQButton, TArmyPlacard, TPlacard` |
| `109` | `0x01b4` | `ApplyStyleDescriptorSlot1B4` | `mid_or_derived_extension` | `<none>` | `thunk_SetCityProductionDialogPictureRectAndMaybeRefresh@0x00403c60` | `THQButton, TArmyPlacard, TPlacard` |
| `110` | `0x01b8` | `CtrlSlot110` | `mid_or_derived_extension` | `<none>` | `thunk_SetControlPictureEntryAndMaybeRefresh@0x00408cdd` | `THQButton, TArmyPlacard, TPlacard` |
| `111` | `0x01bc` | `CtrlSlot111` | `mid_or_derived_extension` | `<none>` | `thunk_LogUnhandledDialogMethodAndReturnFalse@0x00404f66` | `THQButton, TArmyPlacard, TPlacard` |
| `112` | `0x01c0` | `CtrlSlot112` | `mid_or_derived_extension` | `<none>` | `thunk_SetControlStateFlagAndMaybeRefresh@0x0040516e` | `THQButton, TArmyPlacard, TPlacard` |
| `113` | `0x01c4` | `SetStyleStateSlot1C4` | `derived_only_extension` | `<none>` | `<none>` | `THQButton, TArmyPlacard, TPlacard` |
| `114` | `0x01c8` | `SetBitmapSlot1C8` | `derived_only_extension` | `<none>` | `<none>` | `THQButton, TArmyPlacard, TPlacard` |
| `115` | `0x01cc` | `InvokeSlot1CCVirtual` | `derived_only_extension` | `<none>` | `<none>` | `THQButton, TArmyPlacard, TPlacard` |
| `116` | `0x01d0` | `CtrlSlot116` | `derived_only_extension` | `<none>` | `<none>` | `THQButton` |
| `117` | `0x01d4` | `CtrlSlot117` | `trailing_inactive_after_mid_end` | `<none>` | `<none>` | `<none>` |
| `118` | `0x01d8` | `CtrlSlot118` | `trailing_inactive_after_mid_end` | `<none>` | `<none>` | `<none>` |
| `119` | `0x01dc` | `CtrlSlot119` | `trailing_inactive_after_mid_end` | `<none>` | `<none>` | `<none>` |
| `120` | `0x01e0` | `CtrlSlot120` | `trailing_inactive_after_mid_end` | `<none>` | `<none>` | `<none>` |
| `121` | `0x01e4` | `SetControlValueSlot1E4` | `trailing_inactive_after_mid_end` | `<none>` | `<none>` | `<none>` |
| `122` | `0x01e8` | `QueryValueSlot1E8` | `trailing_inactive_after_mid_end` | `<none>` | `<none>` | `<none>` |
| `123` | `0x01ec` | `Slot01EC` | `trailing_inactive_after_mid_end` | `<none>` | `<none>` | `<none>` |
| `124` | `0x01f0` | `Slot01F0` | `trailing_inactive_after_mid_end` | `<none>` | `<none>` | `<none>` |

## Potential Unresolved Slots (TView/TControl)
| Slot | Offset | Interface Method | Classification | Base Target | Mid Target |
|---|---|---|---|---|---|
| `<none>` |  |  |  |  |  |

