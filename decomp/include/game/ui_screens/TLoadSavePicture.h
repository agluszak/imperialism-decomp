#pragma once

#include "game/ui_core/TPicture.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006426b8
class TLoadSavePicture : public TPicture {
public:
  DECLARE_DYNCREATE(TLoadSavePicture)
  virtual ~TLoadSavePicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;             // slot 0x0f 0x0056cd10
  virtual void DoKeyEvent(TToolboxEvent* event) override;   // slot 0x12 0x56d1e0
  virtual void DoPostCreate(int arg) override;              // slot 0x37 0x56bcc0
  virtual void HandleSaveGameSlotSelectionAndPromptFlow();  // slot 0x73 0x56d2a0
  virtual void HandleTurnFlowStateTickOrShowMainMenu(); // slot 0x74 0x56d190

  void RefreshSlotPreviewFromSaveFile(short slotMode);

  bool loadModeFlag; // +0x90
  unsigned char pad91;
  short selectedSlot92; // +0x92 — currently selected save slot (-1 = none)
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
