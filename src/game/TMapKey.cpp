#include "game/TMapKey.h"

#include "game/CString.h"
#include "game/TCountry.h"
#include "game/TDeluxeText.h"
#include "game/TSimMgr.h"
#include "game/TView.h"
#include "game/global_data_tables.h" // g_pSimMgr, g_apTerrainTypeDescriptorTable
#include "game/mapped_flavor_text.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

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
void TMapKey::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);

  short legendX[8] = {0x171, 0x171, 0x171, 0x171, 0x1de, 0x1de, 0x1de, 0x1de};
  // Retail declares only six Y entries but draws seven labels. VC5 places the loop's
  // zeroed RECT immediately after this array, so index 6 reads that RECT's left member
  // after it has been cleared. Preserve the original source/stack shape instead of an
  // invented seventh table entry.
  short legendY[6] = {0x1b8, 0x1d1, 0x187, 0x1a0, 0x1b8, 0x1d1};

  // The loop only walks the first 7 of g_apTerrainTypeDescriptorTable's 23 entries: the
  // array iterator is seeded with the array's own address (0x6a4310) and bounded by a
  // literal end address (0x6a432c) that is only 7*4 bytes past the start, not the full
  // kTerrainTypeDescriptorTableCount span -- confirmed via the raw disassembly's loop
  // bound constant, not guessed from the decompiler (whose stack-slot aliasing across
  // this function's several esp-adjusting setup calls made its own variable naming
  // unreliable, per Hard Rule 6's "ground truth from the tooling" guidance).
  TView* anchor = ownerContext;
  short baseX = static_cast<short>(ownerLocalX + anchor->ownerLocalX);
  short baseY = static_cast<short>(ownerLocalY + anchor->ownerLocalY);

  int sizeXY[2] = {0x46, 0x19};
  CString label;
  COLORREF shadowStyleFlags = 0;
  ResolveUiThemeColor(0x2b68, &shadowStyleFlags);
  TextStyle style;
  style.textColor = 0;
  InitializeUiTextStyleDescriptor(&style, 0, 0xa, 0x2b6b, 3);

  for (int i = 0; i < 7; ++i) {
    TCountry* descriptor = g_apTerrainTypeDescriptorTable[i];
    if (descriptor == nullptr) {
      g_pSimMgr->GetString(0x275d, 2, &label);
    } else {
      descriptor->FormatOverlayTerrainLabelText(&label);
    }

    TDeluxeText* legendText = new TDeluxeText();
    RECT emptyRect = {0, 0, 0, 0};
    CRect zeroRect(&emptyRect);
    int offsetXY[2] = {legendX[i] - baseX, static_cast<short>(legendY[i] - baseY - 0xf)};
    legendText->ConstructTDeluxeTextBaseState(this, offsetXY, sizeXY, &zeroRect, &style, -2);
    legendText->UpdateTextEntrySharedStringAndMaybeNotify(&label, 0);
    legendText->SetEnabled(0, 0);
    legendText->controlTag = 0x6e616d30 + i; // 'nam0'-'nam6'
    legendText->CenterVertically(0);
    legendText->shadowTextColor9C = shadowStyleFlags;
    legendText->dropShadowEnabledA0 = true;
    legendText->SetTextStyle(style, 1);
  }
}

// FUNCTION: IMPERIALISM 0x004fcf80
void TMapKey::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);
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
  COLORREF shadowStyle = 0;
  COLORREF mainStyle = 0;

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 0xa, 0x2b68, 3);
  ResolveUiThemeColor(0x2b6b, &mainStyle);
  ResolveUiThemeColor(0x2b68, &shadowStyle);

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
  COLORREF shadowStyle = 0;
  COLORREF mainStyle = 0;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b68);
  ResolveUiThemeColor(0x2b6b, &mainStyle);
  ResolveUiThemeColor(0x2b68, &shadowStyle);

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
  COLORREF shadowStyle = 0;
  COLORREF mainStyle = 0;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b68);
  ResolveUiThemeColor(0x2b6b, &mainStyle);
  ResolveUiThemeColor(0x2b68, &shadowStyle);

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
  COLORREF shadowStyle = 0;
  COLORREF mainStyle = 0;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b68);
  ResolveUiThemeColor(0x2b6b, &mainStyle);
  ResolveUiThemeColor(0x2b68, &shadowStyle);

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
