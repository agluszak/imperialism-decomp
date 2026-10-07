#pragma once

#include "game/ui_core/TPicture.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006426b8
class TLoadSavePicture : public TPicture {
public:
  DECLARE_DYNCREATE(TLoadSavePicture)
  virtual ~TLoadSavePicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoKeyEvent(TToolboxEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void HandleSaveGameSlotSelectionAndPromptFlow();
  virtual void HandleTurnFlowStateTickOrShowMainMenu();

  void LoadHeader(short slotMode);

  bool loadModeFlag;
  unsigned char pad91;
  short selectedSlot; // currently selected save slot (-1 = none)
  TextStyle styleAt94;
  TextStyle styleAt9e;

  TLoadSavePicture();
};

ASSERT_SIZE(TLoadSavePicture, 0xa8);

// Save-game free functions (TLoadSavePicture TU).
int __cdecl ReadScenarioIndexFromSaveHeader(const char* path);
void __cdecl BuildSavePathStringForMode(CString* out, int saveMode, char* label);
void __cdecl SaveGameWithModeAndOptionalLabel(int mode, char* label);

unsigned char __cdecl BuildSaveSlotPathAndProbeMetadata(int slot, const char* label);
