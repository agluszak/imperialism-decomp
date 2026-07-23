#pragma once

#include "game/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00644540
class TScenarioChooser : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TScenarioChooser)
  virtual ~TScenarioChooser() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;         // slot 0x07 0x57ab30
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;           // slot 0x0f 0x0057a050
  virtual void DoKeyEvent(TToolboxEvent* event) override; // slot 0x12 0x57a310
  virtual void DoPostCreate(int arg) override;            // slot 0x37 0x579b80
  virtual void StartGame();                               // slot 0x74 0x57a350
  virtual void ExitScreen();                              // slot 0x75 0x57a2d0

  // 0x57a6e0, RET 4 (non-virtual thiscall, 1 arg). Confirmed receiver via the write to
  // selectedScenarioIndex142 at +0x1e (MOV word ptr [ecx+0x142],ax) in its opening bytes.
  void LoadScenarioMetadataByIndexIntoUiControlCore(short scenarioIndex);

  TScenarioChooser();

  // Own fields at +0x94..+0x160 (RTTI m_nObjectSize 0x160 vs TNoHilitePicture's 0x94).
  // Ctor (0x45ae60) only chains the base ctor and installs the vtable -- nothing here
  // is written at construction, so most of this block is still unrecovered scenario-
  // selection state.
  // Per-list-row scenario index, indexed by the 'list' TTextList's selectedIndex in
  // DoEvent's commandId==4 branch and passed to
  // LoadScenarioMetadataByIndexIntoUiControlCore.
  short scenarioIndexByListRow94[(0x114 - 0x94) / 2];
  // +0x114 -- how many rows DoPostCreate actually appended to the 'list' control.
  short scenarioListRowCount114;
  unsigned char padding116[2];
  // Per-nation-slot description text + length, passed to the 'desc' TDeluxeText's
  // SetTextEntryFromChars(textChars, textLength) in DoEvent's 'pick' branch, indexed
  // by TMapPreviewView::pendingNation6C.
  char* nationDescriptionTextByMapSelection118[(0x134 - 0x118) / 4];
  short nationDescriptionLengthByMapSelection134[(0x142 - 0x134) / 2];
  // Selected scenario index (-1 = none); read by StartGame and ExitScreen. -1 also
  // short-circuits the whole
  // apply flow.
  short selectedScenarioIndex142;
  // Per-nation-slot state codes, indexed by TMapPreviewView::selectedNation68 and applied
  // via TSimMgr::SetDifficultyLevel.
  int nationStateCodesByMapSelection144[(0x160 - 0x144) / 4];
};
