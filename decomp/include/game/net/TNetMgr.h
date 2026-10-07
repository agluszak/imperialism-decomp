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
  virtual ~TNetMgr() override;
  virtual void Free() override;

  TNetMgr();

  void StartMultiplayerSupport();

  bool Send(NetMessage* message, bool queueOnly);

  bool DefaultUnhandledTurnEventHookReturnsFalse(TurnEventQueuePacket* packet);
  void ReleaseMessage(TurnEventQueuePacket* packet);
  TurnEventQueuePacket* GetMessage();
  bool CheckConnectivityOrShowLocalizedWarningAndReturnReady();
  int GetPlayerID();

  void NoOpDialogModeTagChangedHook(int arg); // 0x5e42a0 (empty)
  void NotifyIfNationMatchesSessionActiveNation(int nationId);

  int Ping();

  void ResetTurnEventQueueRuntimeRecordBuffer();
  bool ResetRuntimeSelectionRecordBufferAndReturnTrue();
  bool ReturnTrueRuntimeCredentialFinalizeStub();

  bool SelectProtocol(int index, int flag, const char* seed);

  unsigned char Host(const char* seedPath, const char* localPlayerName, const char* emptyOrSeed);

  unsigned char SelectGame(int selectionTag, CString* outGameName, const char* seed);

  unsigned char ResetRuntimeProtocolOptionsAndRebuildSelectionSource(TView* provider);

  void HandleError(int errorCode);
};
