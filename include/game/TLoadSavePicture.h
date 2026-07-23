#pragma once

#include "game/TPicture.h"
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
  virtual void HandleTurnFlowStateTickOrPostTurnEvent5DC(); // slot 0x74 0x56d190

  // 0x56c740, RET 4 (non-virtual). Builds the slot's save path (same recipe as
  // BuildSavePathStringForMode) and, when the file exists, reloads its header into a
  // 0x1950-byte buffer and rebuilds the 'map ' preview control from it.
  void RefreshSlotPreviewFromSaveFile(short slotMode);

  // 0 = save picture, nonzero = load picture (the builder writes it, the prompt flow
  // 0x56d2a0 branches on it).
  unsigned char loadModeFlag90; // +0x90
  unsigned char pad91;
  short selectedSlot92; // +0x92 — currently selected save slot (-1 = none)
  // +0x94..+0x9e: a second TextStyle (exactly 10 bytes, matching
  // sizeof(TextStyle)) -- DoEvent's commandId==0xd branch passes
  // &styleAt94 to the newly-selected slot control's InstallTextStyle, and
  // &styleAt9e (below) to the previously-selected one: "selected" vs "unselected" style.
  TextStyle styleAt94;
  // Passed by address to TControl::InstallTextStyle (byte offset 0x1b4, slot
  // 0x6d) on the previously-selected slot control in DoEvent's commandId==0xd branch;
  // exactly fills the tail to ASSERT_SIZE's 0xa8 (0x9e + sizeof(TextStyle)).
  TextStyle styleAt9e;

  TLoadSavePicture();
};

ASSERT_SIZE(TLoadSavePicture, 0xa8);

// Save-game free functions (TLoadSavePicture TU).
int __cdecl ReadScenarioIndexFromSaveHeader(const char* path);
void __cdecl BuildSavePathStringForMode(CString* out, int saveMode, char* label);
// 0x56da50 — top-level save-game driver (see TLoadSavePicture.cpp).
void __cdecl SaveGameWithModeAndOptionalLabel(int mode, char* label);

// 0x56df40: build the save path for `slot` with `label` and probe the file's metadata;
// returns whether the save file exists (turn-event 0xE 'load' receive path).
unsigned char __cdecl BuildSaveSlotPathAndProbeMetadata(int slot, const char* label);
