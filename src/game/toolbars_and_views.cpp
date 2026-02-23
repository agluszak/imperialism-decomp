// Non-trade wrapper classes moved out of trade_screen.
// These wrappers were previously mixed into trade_screen.cpp.

#include "decomp_types.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 ConstructTUberClusterBaseState(void);
undefined4 thunk_ConstructUiResourceEntryBase(void);
undefined4 thunk_ConstructUiResourceEntryType4B0C0(void);
undefined4 thunk_ConstructPictureResourceEntryBase(void);
undefined4 thunk_DestructEngineerDialogBaseState(void);
undefined4 thunk_DestructCityDialogSharedBaseState(void);

struct TradeMoveStepCluster;

namespace {

char g_vtblTArmyToolbar;
char g_pClassDescTArmyToolbar;
char g_vtblTStratReportView;
char g_pClassDescTStratReportView;
char g_vtblTCivToolbar;
char g_pClassDescTCivToolbar;
char g_vtblTArmyInfoView;
char g_pClassDescTArmyInfoView;

struct ArmyToolbarState {
  void *vftable;
  char pad_04[0x88];
};

struct StratReportViewState {
  void *vftable;
  char pad_04[0x60];
};

struct CivToolbarState {
  void *vftable;
  char pad_04[0x88];
};

struct ArmyInfoViewState {
  void *vftable;
  char pad_04[0x8c];
};

class RuntimeBridge {
public:
  static __inline void ConstructTUberClusterBaseState(TradeMoveStepCluster *self)
  {
    reinterpret_cast<void (__fastcall *)(TradeMoveStepCluster *)>(
        ::ConstructTUberClusterBaseState)(self);
  }

  static __inline void ConstructUiResourceEntryBase(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(::thunk_ConstructUiResourceEntryBase)(self);
  }

  static __inline void ConstructUiResourceEntryType4B0C0(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(::thunk_ConstructUiResourceEntryType4B0C0)(self);
  }

  static __inline void ConstructPictureResourceEntryBase(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(::thunk_ConstructPictureResourceEntryBase)(self);
  }

  static __inline void DestructCityDialogSharedBaseState(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(::thunk_DestructCityDialogSharedBaseState)(self);
  }
};

}  // namespace

// FUNCTION: IMPERIALISM 0x0058DE40
ArmyToolbarState *__cdecl CreateTArmyToolbarInstance(void)
{
  ArmyToolbarState *toolbar =
      reinterpret_cast<ArmyToolbarState *>(AllocateWithFallbackHandler(0x8c));
  if (toolbar != 0) {
    RuntimeBridge::ConstructTUberClusterBaseState(
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
  RuntimeBridge::ConstructTUberClusterBaseState(reinterpret_cast<TradeMoveStepCluster *>(toolbar));
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
    RuntimeBridge::ConstructUiResourceEntryBase(view);
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
  RuntimeBridge::ConstructUiResourceEntryBase(view);
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
    RuntimeBridge::ConstructUiResourceEntryType4B0C0(toolbar);
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
  RuntimeBridge::ConstructUiResourceEntryType4B0C0(toolbar);
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
    RuntimeBridge::ConstructPictureResourceEntryBase(view);
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
  RuntimeBridge::ConstructPictureResourceEntryBase(view);
  view->vftable = reinterpret_cast<void *>(&g_vtblTArmyInfoView);
  return view;
}


// FUNCTION: IMPERIALISM 0x005915D0
ArmyInfoViewState *__fastcall DestructTArmyInfoViewAndMaybeFree(
    ArmyInfoViewState *view, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  RuntimeBridge::DestructCityDialogSharedBaseState(view);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)view);
  }
  return view;
}
