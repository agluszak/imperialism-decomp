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
  // slot 0x0a null (0x00000000)
  // slot 0x0b null (0x00000000)

  TNetMgr();

  void StartMultiplayerSupport(); // 0x5e3450

  unsigned char Send(NetMessage* message, bool queueOnly);

  unsigned char DefaultUnhandledTurnEventHookReturnsFalse(TurnEventQueuePacket* packet);
  void FreeTurnEventPacketBuffer(TurnEventQueuePacket* packet);
  TurnEventQueuePacket* PopNextTurnEventPacketOrProcessSpecialQueueRecords();
  unsigned char CheckConnectivityOrShowLocalizedWarningAndReturnReady();
  int GetSessionActiveNationId(); // 0x5e4280

  void NoOpDialogModeTagChangedHook(int arg); // 0x5e42a0 (empty)
  void NotifyIfNationMatchesSessionActiveNation(int nationId);

  int ProbeNationReachabilityAndMarkAwolBitmask();

  void ResetTurnEventQueueRuntimeRecordBuffer(); // 0x5e3ef0
  unsigned char ResetRuntimeSelectionRecordBufferAndReturnTrue(); // 0x5e34d0
  unsigned char ReturnTrueRuntimeCredentialFinalizeStub(); // 0x5e3c00

  unsigned char OpenRuntimeSelectionSourceByIndexAndCopyPath(int index, int flag,
                                                             const char* seed); // 0x5e3a60

  unsigned char
  Host(const char* seedPath,
                                                      const char* localPlayerName,
                                                      const char* emptyOrSeed); // 0x5e3ad0

  unsigned char SelectGame(int selectionTag, CString* outGameName,
                                                            const char* seed); // 0x5e3c20

  unsigned char ResetRuntimeProtocolOptionsAndRebuildSelectionSource(TView* provider); // 0x5e39a0

  void HandleError(int errorCode);
};
