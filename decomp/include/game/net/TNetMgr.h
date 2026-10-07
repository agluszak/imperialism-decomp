#pragma once

#include "game/app/TObject.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

struct NetMessage;
struct TurnEventQueuePacket;
class TView;

// VTABLE: IMPERIALISM 0x0066fa20
class TNetMgr : public TObject {
public:
  DECLARE_DYNCREATE(TNetMgr)
  virtual ~TNetMgr() override;  // slot 0x01 (scalar deleting destructor)
  virtual void Free() override; // slot 0x07 0x5e3470

  TNetMgr();

  void StartMultiplayerSupport(); // 0x5e3450

  bool Send(NetMessage* message, bool queueOnly);

  bool DefaultUnhandledTurnEventHookReturnsFalse(TurnEventQueuePacket* packet);
  void ReleaseMessage(TurnEventQueuePacket* packet);
  TurnEventQueuePacket* GetMessage();
  bool CheckConnectivityOrShowLocalizedWarningAndReturnReady();
  int GetPlayerID(); // 0x5e4280

  void NoOpDialogModeTagChangedHook(int arg); // 0x5e42a0 (empty)
  void NotifyIfNationMatchesSessionActiveNation(int nationId);

  int Ping();

  void ResetTurnEventQueueRuntimeRecordBuffer();         // 0x5e3ef0
  bool ResetRuntimeSelectionRecordBufferAndReturnTrue(); // 0x5e34d0
  bool ReturnTrueRuntimeCredentialFinalizeStub();        // 0x5e3c00

  bool SelectProtocol(int index, int flag,
                      const char* seed); // 0x5e3a60

  unsigned char Host(const char* seedPath, const char* localPlayerName,
                     const char* emptyOrSeed); // 0x5e3ad0

  unsigned char SelectGame(int selectionTag, CString* outGameName,
                           const char* seed); // 0x5e3c20

  unsigned char ResetRuntimeProtocolOptionsAndRebuildSelectionSource(TView* provider); // 0x5e39a0

  void HandleError(int errorCode);
};
