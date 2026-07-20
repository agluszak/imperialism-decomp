#include "game/TMapKey.h"

#include "game/CString.h"
#include "game/TCountry.h"
#include "game/TSimMgr.h"
#include "game/TView.h"
#include "game/global_data_tables.h"        // g_pSimMgr, g_apTerrainTypeDescriptorTable
#include "game/localization_text_helpers.h" // scanBracketExpressions
#include "game/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x00430900
// TMapKey::`scalar deleting destructor'
TMapKey::~TMapKey() {}
// SYNTHETIC: IMPERIALISM 0x004fc9c0
// TMapKey::CreateObject

// SYNTHETIC: IMPERIALISM 0x004fca70
// TMapKey::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMapKey, TPicture)

TMapKey::TMapKey() {}

// FUNCTION: IMPERIALISM 0x004fcac0
void TMapKey::NoOpUiLifecycleHook(int arg) {
  TPicture::NoOpUiLifecycleHook(arg);
  // TODO: the original then loops over all 23 g_apTerrainTypeDescriptorTable entries
  // (kTerrainTypeDescriptorTableCount), for each one: gets its label (GetString(0x275d,2)
  // for a null descriptor, else descriptor->FormatOverlayTerrainLabelText -- 0x405245/
  // 0x4d7860), allocates a real `new TDeluxeText()` (operator_new(0xa4) + the standard
  // TStaticText/TTEView/TDeluxeText layered ctor chain, matching the established
  // ConstructTDeluxeTextBaseState(owner, offset[2], size[2], &rect, &style, -2) pattern used
  // elsewhere e.g. TTechItemView.cpp), and positions it from two 8-entry x/y coordinate
  // tables (stack literals at 0x4fcaef-0x4fcb88) offset by (this->ownerLocalX +
  // ownerContext->ownerLocalX, this->ownerLocalY + ownerContext->ownerLocalY - 0xf). The
  // Ghidra decompile of 0x4fcac0 mis-resolves several stack slots as aliased/reused
  // (local_84, local_88.m_pchData) across the multiple esp-adjusting calls in the setup
  // block (0x605797/0x4093cc/0x402a7c), so the exact origin of the per-iteration base
  // offsets needs re-deriving from the raw disassembly rather than trusted from the
  // decompiler output -- left unmodeled pending that pass.
}

// FUNCTION: IMPERIALISM 0x004fcf80
void TMapKey::ApplyRectSlot110(RECT* rectBuffer) {
  TPicture::ApplyRectSlot110(rectBuffer);
  switch (this->viewMode90) {
  case 0:
    RenderMapHintOverlayMode0();
    break;
  case 1:
    RenderMapHintOverlayMode1();
    break;
  case 2:
    RenderMapHintOverlayMode2();
    break;
  case 4:
    RenderMapHintOverlayMode4();
    break;
  }
}

// Legend labels for view mode 0: a heading and a body line, each drawn twice
// (offset drop shadow then main color) at coordinates relative to the anchor view.
// FUNCTION: IMPERIALISM 0x004fd000
void TMapKey::RenderMapHintOverlayMode0() {
  TView* anchor = this->ownerContext;
  short baseX = (short)this->ownerLocalX + (short)anchor->ownerLocalX;
  short baseY = (short)this->ownerLocalY + (short)anchor->ownerLocalY;

  CString label;
  int shadowStyle = 0;
  int mainStyle = 0;

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 0xa, 0x2b68, 3);
  MapUiThemeCodeToStyleFlags(0x2b6b, &mainStyle);
  MapUiThemeCodeToStyleFlags(0x2b68, &shadowStyle);

  g_pSimMgr->GetString(0x2733, 5, &label);
  short x = 0x1de - baseX;
  short y = 0x1d1 - baseY;
  SetQuickDrawColorAndSyncGlobals(shadowStyle);
  SetQuickDrawTextOriginWithContextOffset(x + 1, y + 1);
  DrawTextWithCachedQuickDrawStyleState(&label);
  SetQuickDrawColorAndSyncGlobals(mainStyle);
  SetQuickDrawTextOriginWithContextOffset(x, y);
  DrawTextWithCachedQuickDrawStyleState(&label);

  g_pSimMgr->GetString(0x2733, 0x1e, &label);
  short x2 = 0x1af - baseX;
  short y2 = 0x171 - baseY;
  SetQuickDrawColorAndSyncGlobals(shadowStyle);
  SetQuickDrawTextOriginWithContextOffset(x2 + 1, y2 + 1);
  DrawTextWithCachedQuickDrawStyleState(&label);
  SetQuickDrawColorAndSyncGlobals(mainStyle);
  SetQuickDrawTextOriginWithContextOffset(x2, y2);
  DrawTextWithCachedQuickDrawStyleState(&label);
}

// Legend labels for view mode 4: seven numbered labels at table coordinates
// plus a centered terrain-descriptor label, each drawn twice for a drop shadow.
// FUNCTION: IMPERIALISM 0x004fd220
void TMapKey::RenderMapHintOverlayMode4() {
  TView* anchor = this->ownerContext;
  short baseX = (short)this->ownerLocalX + (short)anchor->ownerLocalX;
  short baseY = (short)this->ownerLocalY + (short)anchor->ownerLocalY;
  short descriptorIndex = *(short*)((char*)anchor->ownerContext + 0x98);

  short xTable[7] = {0x169, 0x169, 0, 0x1e5, 0x1e5, 0x1e5, 0x1e5};
  short yTable[7] = {0x190, 0x1a3, 0x1cb, 0x187, 0x198, 0x1a9, 0x1cb};
  xTable[2] = descriptorIndex;

  CString label;
  CString terrainName;
  CString expanded;
  int shadowStyle = 0;
  int mainStyle = 0;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b68);
  MapUiThemeCodeToStyleFlags(0x2b6b, &mainStyle);
  MapUiThemeCodeToStyleFlags(0x2b68, &shadowStyle);

  for (int k = 0; k < 7; ++k) {
    g_pSimMgr->GetString(0x2733, (short)(6 + k), &label);
    short x = xTable[k] - baseX;
    short y = yTable[k] - baseY;
    SetQuickDrawColorAndSyncGlobals(shadowStyle);
    SetQuickDrawTextOriginWithContextOffset(x + 1, y + 1);
    DrawTextWithCachedQuickDrawStyleState(&label);
    SetQuickDrawColorAndSyncGlobals(mainStyle);
    SetQuickDrawTextOriginWithContextOffset(x, y);
    DrawTextWithCachedQuickDrawStyleState(&label);
  }

  g_pSimMgr->GetString(0x2733, 0x1f, &label);
  g_apTerrainTypeDescriptorTable[descriptorIndex]->FormatOverlayTerrainLabelText(&terrainName);
  scanBracketExpressions(g_pSimMgr, &expanded, static_cast<const char*>(label),
                         static_cast<const char*>(terrainName));
  short cy = 0x172 - baseY;
  short width = MeasureTextExtentWithCachedQuickDrawStyle(&expanded);
  short cx = 0x1bd - width / 2 - baseX;
  SetQuickDrawColorAndSyncGlobals(shadowStyle);
  SetQuickDrawTextOriginWithContextOffset(cx + 1, cy + 1);
  DrawTextWithCachedQuickDrawStyleState(&expanded);
  SetQuickDrawColorAndSyncGlobals(mainStyle);
  SetQuickDrawTextOriginWithContextOffset(cx, cy);
  DrawTextWithCachedQuickDrawStyleState(&expanded);
}

// Legend labels for view mode 1: three numbered labels at table coordinates plus
// a centered terrain-descriptor label, each drawn twice for a drop shadow.
// FUNCTION: IMPERIALISM 0x004fd5c0
void TMapKey::RenderMapHintOverlayMode1() {
  TView* anchor = this->ownerContext;
  short baseX = (short)this->ownerLocalX + (short)anchor->ownerLocalX;
  short baseY = (short)this->ownerLocalY + (short)anchor->ownerLocalY;
  short descriptorIndex = *(short*)((char*)anchor->ownerContext + 0x98);

  short xTable[3] = {0, 0x1f2, 0x16b};
  short yTable[3] = {0x1a9, 0x1a9, 0x1cb};
  xTable[0] = descriptorIndex;

  CString label;
  CString terrainName;
  CString expanded;
  int shadowStyle = 0;
  int mainStyle = 0;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b68);
  MapUiThemeCodeToStyleFlags(0x2b6b, &mainStyle);
  MapUiThemeCodeToStyleFlags(0x2b68, &shadowStyle);

  for (int k = 0; k < 3; ++k) {
    g_pSimMgr->GetString(0x2733, (short)(0xe + k), &label);
    short x = xTable[k] - baseX;
    short y = yTable[k] - baseY;
    SetQuickDrawColorAndSyncGlobals(shadowStyle);
    SetQuickDrawTextOriginWithContextOffset(x + 1, y + 1);
    DrawTextWithCachedQuickDrawStyleState(&label);
    SetQuickDrawColorAndSyncGlobals(mainStyle);
    SetQuickDrawTextOriginWithContextOffset(x, y);
    DrawTextWithCachedQuickDrawStyleState(&label);
  }

  g_pSimMgr->GetString(0x2733, 0xd, &label);
  g_apTerrainTypeDescriptorTable[descriptorIndex]->FormatOverlayTerrainLabelText(&terrainName);
  scanBracketExpressions(g_pSimMgr, &expanded, static_cast<const char*>(label),
                         static_cast<const char*>(terrainName));
  short cy = 0x172 - baseY;
  short width = MeasureTextExtentWithCachedQuickDrawStyle(&expanded);
  short cx = 0x1bd - width / 2 - baseX;
  SetQuickDrawColorAndSyncGlobals(shadowStyle);
  SetQuickDrawTextOriginWithContextOffset(cx + 1, cy + 1);
  DrawTextWithCachedQuickDrawStyleState(&expanded);
  SetQuickDrawColorAndSyncGlobals(mainStyle);
  SetQuickDrawTextOriginWithContextOffset(cx, cy);
  DrawTextWithCachedQuickDrawStyleState(&expanded);
}

// Legend labels for view mode 2: a heading label, a three-label loop at table
// coordinates, a fixed-position label, and a centered terrain-descriptor label,
// each drawn twice for a drop shadow.
// FUNCTION: IMPERIALISM 0x004fd910
void TMapKey::RenderMapHintOverlayMode2() {
  TView* anchor = this->ownerContext;
  short baseX = (short)this->ownerLocalX + (short)anchor->ownerLocalX;
  short baseY = (short)this->ownerLocalY + (short)anchor->ownerLocalY;
  short descriptorIndex = *(short*)((char*)anchor->ownerContext + 0x98);

  short xTable[3] = {0x153, 0x90, 0x198};
  short yTable[3] = {0x20, 0x4c, 0x68};

  CString label;
  CString terrainName;
  CString expanded;
  int shadowStyle = 0;
  int mainStyle = 0;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b68);
  MapUiThemeCodeToStyleFlags(0x2b6b, &mainStyle);
  MapUiThemeCodeToStyleFlags(0x2b68, &shadowStyle);

  g_pSimMgr->GetString(0x2733, 0x12, &label);
  short x1 = 0x153 - baseX;
  short y1 = 0x198 - baseY;
  SetQuickDrawColorAndSyncGlobals(shadowStyle);
  SetQuickDrawTextOriginWithContextOffset(x1 + 1, y1 + 1);
  DrawTextWithCachedQuickDrawStyleState(&label);
  SetQuickDrawColorAndSyncGlobals(mainStyle);
  SetQuickDrawTextOriginWithContextOffset(x1, y1);
  DrawTextWithCachedQuickDrawStyleState(&label);

  for (int k = 0; k < 3; ++k) {
    g_pSimMgr->GetString(0x2733, (short)(0x13 + k), &label);
    short x = xTable[k];
    short y = yTable[k];
    SetQuickDrawColorAndSyncGlobals(shadowStyle);
    SetQuickDrawTextOriginWithContextOffset(x + 1, y + 1);
    DrawTextWithCachedQuickDrawStyleState(&label);
    SetQuickDrawColorAndSyncGlobals(mainStyle);
    SetQuickDrawTextOriginWithContextOffset(x, y);
    DrawTextWithCachedQuickDrawStyleState(&label);
  }

  g_pSimMgr->GetString(0x2733, 0x60, &label);
  SetQuickDrawColorAndSyncGlobals(shadowStyle);
  SetQuickDrawTextOriginWithContextOffset(0x91, 0x69);
  DrawTextWithCachedQuickDrawStyleState(&label);
  SetQuickDrawColorAndSyncGlobals(mainStyle);
  SetQuickDrawTextOriginWithContextOffset(0x90, 0x68);
  DrawTextWithCachedQuickDrawStyleState(&label);

  g_pSimMgr->GetString(0x2733, 0x11, &label);
  g_apTerrainTypeDescriptorTable[descriptorIndex]->FormatOverlayTerrainLabelText(&terrainName);
  scanBracketExpressions(g_pSimMgr, &expanded, static_cast<const char*>(label),
                         static_cast<const char*>(terrainName));
  short cy = 0x172 - baseY;
  short width = MeasureTextExtentWithCachedQuickDrawStyle(&expanded);
  short cx = 0x1bd - width / 2 - baseX;
  SetQuickDrawColorAndSyncGlobals(shadowStyle);
  SetQuickDrawTextOriginWithContextOffset(cx + 1, cy + 1);
  DrawTextWithCachedQuickDrawStyleState(&expanded);
  SetQuickDrawColorAndSyncGlobals(mainStyle);
  SetQuickDrawTextOriginWithContextOffset(cx, cy);
  DrawTextWithCachedQuickDrawStyleState(&expanded);
}
