#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TToolBarClusterVtbl;
class TView;
class TEventHandler;
class TControl;
class TCursorControlPanel;
class TDiplomacyMapView;

// TODO(manifest): describe TViewMgr and its role. Base edge (TObject) recovered from RTTI
// CRuntimeClass chain: TViewMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066f120
class TViewMgr : public TObject {
public:
  // === BEGIN GENERATED DECLS (TViewMgr) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TViewMgr)
  virtual ~TViewMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5d5250
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5d5200
  virtual void Free() override;                    // slot 0x07 0x5d51e0
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual void LoadTurnEventCursorTable();                                     // slot 0x0a 0x5d5100
  virtual void HandleTurnEventVtableSlot2CInitializeHotKeyDialog();            // slot 0x0b 0x5dcaa0
  virtual void UpdatePaletteIndexFromTurnEventCode(int eventCode);             // slot 0x0c 0x5d5780
  virtual void ApplyTurnEventPaletteColorByEventCode(int eventCode);           // slot 0x0d 0x5d5750
  virtual int ClassifyTurnStateForOverlayMode();                               // slot 0x0e 0x5d5960
  virtual void BuildAndShowTurnOverlayByMode(int overlayMode, int contextArg); // slot 0x0f 0x5d6480
  virtual void HandleTurnEventVtableSlot40RefreshGoldDialog();                 // slot 0x10 0x5d57b0
  virtual void ComputeTurnEventDialogPlacementByCode(TView* dialogView,
                                                     POINT* outPlacement); // slot 0x11 0x5d69b0
  virtual void RefreshMainViewNationIndicatorForCurrentTurnEvent();        // slot 0x12 0x5d6b70
  // === END GENERATED DECLS (TViewMgr) ===

  // Extended UI-runtime virtuals (same object as g_pUiRuntimeContext @ 0x006A21BC).
  virtual void DispatchTurnEventSlot4C(short eventCode, int payload); // 0x4c
  virtual void UiRuntimeSlot50(int payload);                          // 0x50
  virtual short GetPendingTurnOverlayCode();                          // 0x54
  virtual void UiRuntimeSlot58();                                     // 0x58
  virtual void UiRuntimeSlot5C();                                     // 0x5c
  virtual void UiRuntimeSlot60();                                     // 0x60
  virtual void UiRuntimeSlot64();                                     // 0x64

  // UI runtime helper functions
  virtual void AddPendingTurnOverlayCode(int modeValue); // 0x68
  virtual void UiRuntimeSlot6C();                        // 0x6c
  virtual void UiRuntimeSlot70();                        // 0x70
  virtual void UiRuntimeSlot74();                        // 0x74
  virtual void UiRuntimeSlot78();                        // 0x78
  virtual void UiRuntimeSlot7C();                        // 0x7c
  virtual void UiRuntimeSlot80();                        // 0x80
  virtual void UiRuntimeSlot84();                        // 0x84
  virtual void UiRuntimeSlot88();                        // 0x88
  virtual void UiRuntimeSlot8C(int arg);                 // 0x8c
  virtual char RequestDiplomacyDecisionSlot90(int sourceNation, int targetNation,
                                              int proposalCode); // 0x90
  virtual char RequestDecisionSlot94(int sourceNation, int arg1, int arg2,
                                     int promptCode); // 0x94
  virtual void DispatchDecisionSlot98(int sourceNation, int arg2, int arg3,
                                      int targetNation);                // 0x98
  virtual void UiRuntimeSlot9C();                                       // 0x9c
  virtual void UiRuntimeSlotA0();                                       // 0xa0
  virtual void UiRuntimeSlotA4(int payload, TEventHandler* waitTarget); // 0xa4
  virtual void UiRuntimeSlotA8();                                       // 0xa8
  // Forwards to g_pStrategicMapViewSystem's own vtable slot 0x5c/0x60/0x68/0x6c/
  // 0x70/0x74 (TMacViewMgr) -- verified via disassembly (0057db14-style pattern:
  // `mov ecx,[g_pStrategicMapViewSystem]; mov eax,[ecx]; jmp [eax+0xNN]`, no
  // wrapping logic). Real orig names embed the target slot's byte offset. bd
  // imperialism-decomp-kdm.
  virtual void InvokeStrategicMapViewMethod5C(); // 0xac 0x5d7f70
  virtual void InvokeStrategicMapViewMethod60(short param1); // 0xb0 0x5d7f90
  virtual void UiRuntimeSlotB4();                                       // 0xb4
  virtual void UiRuntimeSlotB8();                                       // 0xb8
  virtual void UiRuntimeSlotBC();                                       // 0xbc
  virtual undefined InvokeStrategicMapViewMethod68(); // 0xc0 0x5dc180
  virtual undefined InvokeStrategicMapViewMethod70(); // 0xc4 0x5dc1c0
  virtual undefined InvokeStrategicMapViewMethod74(); // 0xc8 0x5dc1a0
  virtual void InvokeStrategicMapViewMethod6C(); // 0xcc 0x5dc160
  virtual void UiRuntimeSlotD0();                                       // 0xd0
  virtual void UiRuntimeSlotD4(int arg);                                // 0xd4
  virtual void UiRuntimeSlotD8();                                       // 0xd8
  virtual int ShowConstructionOptionsDialog();                          // 0xdc
  virtual void UiRuntimeSlotE0();                                       // 0xe0
  virtual void UiRuntimeSlotE4();                                       // 0xe4
  virtual void UiRuntimeSlotE8();                                       // 0xe8
  virtual void UiRuntimeSlotEC();                                       // 0xec
  virtual void UiRuntimeSlotF0();                                       // 0xf0
  virtual void UiRuntimeSlotF4();                                       // 0xf4
  virtual void UiRuntimeSlotF8();                                       // 0xf8
  virtual void NoOpTurnEventStateVtableSlotFC(); // 0xfc 0x5dbd10 -- real body is a bare `ret`
  virtual void UiRuntimeSlot100();                                      // 0x100
  virtual void UiRuntimeSlot104();                                      // 0x104
  virtual void UiRuntimeSlot108();                                      // 0x108
  virtual void UiRuntimeSlot10C();                                      // 0x10c
  virtual void UiRuntimeSlot110();                                      // 0x110

  void ApplyLegendSplitSlot34(int split) {
    ApplyTurnEventPaletteColorByEventCode(split);
  }
  void QueueTurnStatusPromptSlot3C(int promptIndex, int payload) {
    BuildAndShowTurnOverlayByMode(promptIndex, payload);
  }
  void RefreshViewSlot48() {
    RefreshMainViewNationIndicatorForCurrentTurnEvent();
  }

  int MapTurnEventCodeToPaletteIndex(int eventCode);
  undefined4 RunControlStringProviderAndDispatchLocalizedMessage(CString* messageString);
  undefined1 DispatchLocalizedUiMessageWithTemplateA13A0(int overlayMode, CString* messageCString);
  undefined1 DispatchLocalizedUiMessageWithTemplate(int templateKind);

  // Object layout recovered from ctor 0x5d5060 / ReadFrom 0x5d5200 /
  // LoadTurnEventCursorTable 0x5d5100. Field names past the event code are
  // provisional. Total size 0xfc, base TObject = 0x4.
  short currentTurnEventCode;              // +0x04 (turn-event dispatch code)
  short pad06;                             // +0x06
  unsigned int turnStateSeedLo;            // +0x08 (seeded from g_dat_006a5b58)
  unsigned int turnStateSeedHi;            // +0x0c (seeded from g_dat_006a5b5c)
  unsigned char field10;                   // +0x10
  unsigned char pad11[3];                  // +0x11
  void* cursorTable[0x36];                 // +0x14 .. 0xeb (54 turn-event cursor handles)
  short fieldEc;                           // +0xec
  short padEe;                             // +0xee
  class TMapUberPicture* mapUberPictureF0; // +0xf0
  unsigned int fieldF4;                    // +0xf4
  short fieldF8;                           // +0xf8
  short padFa;                             // +0xfa

  TViewMgr();
};

ASSERT_SIZE(TViewMgr, 0xfc);

// === BEGIN GENERATED (TViewMgr) — refreshed by `just gen-class TViewMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066f120 (19 slots), object size 0xfc, base TObject
//   slot 0x00  byte 0x00  0x005d5040  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x005d50b0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x005d5250  override  WriteTo
//   slot 0x06  byte 0x18  0x005d5200  override  ReadFrom
//   slot 0x07  byte 0x1c  0x005d51e0  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x005d5100  override  LoadTurnEventCursorTable
//   slot 0x0b  byte 0x2c  0x005dcaa0  override  HandleTurnEventVtableSlot2CInitializeHotKeyDialog
//   slot 0x0c  byte 0x30  0x005d5780  override  UpdatePaletteIndexFromTurnEventCode
//   slot 0x0d  byte 0x34  0x005d5750  override  ApplyTurnEventPaletteColorByEventCode
//   slot 0x0e  byte 0x38  0x005d5960  override  ClassifyTurnStateForOverlayMode
//   slot 0x0f  byte 0x3c  0x005d6480  override  BuildAndShowTurnOverlayByMode
//   slot 0x10  byte 0x40  0x005d57b0  override  HandleTurnEventVtableSlot40RefreshGoldDialog
//   slot 0x11  byte 0x44  0x005d69b0  override  ComputeTurnEventDialogPlacementByCode
//   slot 0x12  byte 0x48  0x005d6b70  override  RefreshMainViewNationIndicatorForCurrentTurnEvent
// object size 0xfc (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TViewMgr) ===
