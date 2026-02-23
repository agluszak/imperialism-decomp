// Included by src/game/trade_screen.cpp.
// Contains toolbar/view wrapper quads (address-ordered).

// FUNCTION: IMPERIALISM 0x0058DE40
ArmyToolbarState *__cdecl CreateTArmyToolbarInstance(void)
{
  ArmyToolbarState *toolbar =
      reinterpret_cast<ArmyToolbarState *>(AllocateWithFallbackHandler(0x8c));
  if (toolbar != 0) {
    TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(
        reinterpret_cast<TradeMoveStepCluster *>(toolbar));
    toolbar->vftable = reinterpret_cast<void *>(&g_vtblTArmyToolbar);
  }
  return toolbar;
}




// FUNCTION: IMPERIALISM 0x0058DEC0
void *__cdecl GetTArmyToolbarClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTArmyToolbar);
}




// FUNCTION: IMPERIALISM 0x0058DEE0
ArmyToolbarState *__fastcall ConstructTArmyToolbarBaseState(ArmyToolbarState *toolbar)
{
  TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(
      reinterpret_cast<TradeMoveStepCluster *>(toolbar));
  toolbar->vftable = reinterpret_cast<void *>(&g_vtblTArmyToolbar);
  return toolbar;
}




// FUNCTION: IMPERIALISM 0x0058DF10
ArmyToolbarState *__fastcall DestructTArmyToolbarAndMaybeFree(
    ArmyToolbarState *toolbar, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)toolbar);
  }
  return toolbar;
}



// FUNCTION: IMPERIALISM 0x0058E330
StratReportViewState *__cdecl CreateTStratReportViewInstance(void)
{
  StratReportViewState *view = reinterpret_cast<StratReportViewState *>(
      AllocateWithFallbackHandler(100));
  if (view != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(view);
    view->vftable = reinterpret_cast<void *>(&g_vtblTStratReportView);
  }
  return view;
}



// FUNCTION: IMPERIALISM 0x0058E3A0
void *__cdecl GetTStratReportViewClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTStratReportView);
}



// FUNCTION: IMPERIALISM 0x0058E3C0
StratReportViewState *__fastcall ConstructTStratReportViewBaseState(StratReportViewState *view)
{
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(view);
  view->vftable = reinterpret_cast<void *>(&g_vtblTStratReportView);
  return view;
}



// FUNCTION: IMPERIALISM 0x0058E3F0
StratReportViewState *__fastcall DestructTStratReportViewAndMaybeFree(
    StratReportViewState *view, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)view);
  }
  return view;
}



// FUNCTION: IMPERIALISM 0x0058EA00
CivToolbarState *__cdecl CreateTCivToolbarInstance(void)
{
  CivToolbarState *toolbar =
      reinterpret_cast<CivToolbarState *>(AllocateWithFallbackHandler(0x8c));
  if (toolbar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryType4B0C0(toolbar);
    toolbar->vftable = reinterpret_cast<void *>(&g_vtblTCivToolbar);
  }
  return toolbar;
}



// FUNCTION: IMPERIALISM 0x0058EA80
void *__cdecl GetTCivToolbarClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTCivToolbar);
}



// FUNCTION: IMPERIALISM 0x0058EAA0
CivToolbarState *__fastcall ConstructTCivToolbarBaseState(CivToolbarState *toolbar)
{
  TradeScreenRuntimeBridge::ConstructUiResourceEntryType4B0C0(toolbar);
  toolbar->vftable = reinterpret_cast<void *>(&g_vtblTCivToolbar);
  return toolbar;
}



// FUNCTION: IMPERIALISM 0x0058EAD0
CivToolbarState *__fastcall DestructTCivToolbarAndMaybeFree(
    CivToolbarState *toolbar, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)toolbar);
  }
  return toolbar;
}


// FUNCTION: IMPERIALISM 0x00591500
ArmyInfoViewState *__cdecl CreateTArmyInfoViewInstance(void)
{
  ArmyInfoViewState *view = reinterpret_cast<ArmyInfoViewState *>(
      AllocateWithFallbackHandler(0x90));
  if (view != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(view);
    view->vftable = reinterpret_cast<void *>(&g_vtblTArmyInfoView);
  }
  return view;
}


// FUNCTION: IMPERIALISM 0x00591580
void *__cdecl GetTArmyInfoViewClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTArmyInfoView);
}


// FUNCTION: IMPERIALISM 0x005915A0
ArmyInfoViewState *__fastcall ConstructTArmyInfoViewBaseState(ArmyInfoViewState *view)
{
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(view);
  view->vftable = reinterpret_cast<void *>(&g_vtblTArmyInfoView);
  return view;
}


// FUNCTION: IMPERIALISM 0x005915D0
ArmyInfoViewState *__fastcall DestructTArmyInfoViewAndMaybeFree(
    ArmyInfoViewState *view, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(view);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)view);
  }
  return view;
}
