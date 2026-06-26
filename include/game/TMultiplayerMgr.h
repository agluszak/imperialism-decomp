#pragma once

#include "compat.h"
#include "game/TEventHandler.h"
#include "game/mfc.h"

class TStream;

// Multiplayer session / game-flow manager (g_pGameFlowState). Inherits the shared
// TEventHandler control surface used by UI roots; vtable @ 0x0065c030.
// VTABLE: IMPERIALISM 0x0065c030
class TMultiplayerMgr : public TEventHandler {
public:
  enum { kNationSlotCount = 7 };

  int nationStatusControlSlots[8];              // +0x20
  int field40;                                  // +0x40
  int diplomacyQueueContext;                    // +0x44 — child handler for queue routing
  int nationSessionIds[kNationSlotCount];       // +0x48
  int queueSyncDword;                           // +0x64
  char processPrimaryEventQueue;                // +0x68
  char processSecondaryEventQueue;              // +0x69
  unsigned char pad6a[2];
  int primaryTurnEventQueueHead;                // +0x6c
  int secondaryTurnEventQueueHead;              // +0x70
  CString gameNameString;                       // +0x74
  CString defaultNationTextSlots[kNationSlotCount]; // +0x78
  CString nationDisplayNameSlots[kNationSlotCount]; // +0x94
  CString playerNameString;                     // +0xb0
  CString playerNameMirror;                     // +0xb4
  CString fieldb8;                              // +0xb8
  int nationStatusTags[kNationSlotCount];       // +0xbc — four-cc tags ('suna', 'lwoa', …)
  int sessionPhaseTag;                          // +0xd8 — four-cc phase tag ('adam', 'init', …)
  unsigned char activeNationTagIndex;           // +0xdc
  unsigned char padDd[7];
  unsigned char sessionReadyFlag;               // +0xe4
  unsigned char padE5[7];
  int activeNationSlotIndex;                    // +0xec
  int pendingNationSlotIndex;                   // +0xf0
  unsigned char fieldF4;                        // +0xf4
  unsigned char padF5[3];

  virtual CRuntimeClass* GetRuntimeClass() const override;          // slot 0x00 0x542650
  virtual ~TMultiplayerMgr();                                       // slot 0x01 0x5427e0
  virtual void WriteTo(TStream* stream) override;                   // slot 0x05 0x542ff0
  virtual void ReadFrom(TStream* stream) override;                  // slot 0x06 0x542be0
  virtual void Free() override;                                     // slot 0x07 0x542b10
  virtual char CanHandleCityDialogActionFalse(int action) override; // slot 0x13 0x544e30
  virtual undefined
  InitializeMultiplayerManagerForSessionContext(CString param_1); // slot 0x25 0x542900

  TMultiplayerMgr();
};

ASSERT_SIZE(TMultiplayerMgr, 0xf8);
