#pragma once

#include "decomp_types.h"

#include "game/mfc.h"

#include <dplay.h>
#include <dplobby.h>

class TView;
class TRadioTextCluster;

struct RuntimeSelectionRecord {
  GUID providerGuid;
  CString label;

  ~RuntimeSelectionRecord();
};

struct WNetSelectionRecord {
  GUID providerGuid;
  CString label;

  ~WNetSelectionRecord();
};

IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR

// VTABLE: IMPERIALISM 0x0066f9c0
class TDirectPlaySessionManagerBase {
public:
  TDirectPlaySessionManagerBase() : directPlayInterface(0), directPlayLobby(0) {}
  ~TDirectPlaySessionManagerBase();

  virtual BOOL OnEnumerateServiceProvider(LPGUID providerGuid, LPSTR providerName,
                                          DWORD majorVersion, DWORD minorVersion);
  virtual BOOL OnDirectPlayAssertion111(void* arg1, void* arg2, void* arg3, void* arg4);
  virtual BOOL OnEnumerateJoinableSession(const DPSESSIONDESC2* sessionDescription, DWORD* timeout,
                                          DWORD flags);
  virtual void InitializeSessionDescription();
  virtual void ResetSessionDescription();
  virtual BOOL GetRuntimeSelectionAuxStatus(void* value);
  BOOL ConnectDirectPlayFromLobbySettingsAndStoreResult();
  virtual BOOL ExtendEnumSessionsTimeoutWhileCtrlHeld(DWORD* timeoutMs);
  virtual BOOL SelectRuntimeProvider(GUID* providerGuid);
  virtual BOOL ShowJoinGameSelectionDialogAndCaptureChoice(GUID* selectedSessionGuid);

  BOOL GetPlayerData(DPID playerId, void* buffer, DWORD* sizeInOut);
  BOOL CreateDirectPlayLobbyAndStoreResult();
  BOOL FindHostPlayerIdByEnumeration();
  // Free the runtime selection entries and release the DirectPlay interfaces.
  void ResetRuntimeSelectionRecordBuffer();

  IDirectPlay2* directPlayInterface;
  IDirectPlayLobbyA* directPlayLobby;
  int lastErrorCode;
  DPSESSIONDESC2 sessionDescription;
  int localPlayerId;
  int broadcastPlayerId;
  char joinGameSeed[32];
  char runtimeSelectionSeed[32];
};
ASSERT_SIZE(TDirectPlaySessionManagerBase, 0xa8);

// VTABLE: IMPERIALISM 0x0066f9f0
class TWNetSessionManager : public TDirectPlaySessionManagerBase {
public:
  CString joinGamePlayerName;
  int joinGamePlayerDataTag;
  TRadioTextCluster* activeProtocolControl;

  TWNetSessionManager();
  ~TWNetSessionManager(); // frees the serialized-record scratch arrays
  virtual BOOL OnEnumerateServiceProvider(LPGUID providerGuid, LPSTR providerName,
                                          DWORD majorVersion, DWORD minorVersion) override;
  virtual BOOL OnEnumerateJoinableSession(const DPSESSIONDESC2* sessionDescription, DWORD* timeout,
                                          DWORD flags) override;
  virtual void InitializeSessionDescription() override;
  virtual void ResetSessionDescription() override;
  virtual BOOL ShowJoinGameSelectionDialogAndCaptureChoice(GUID* selectedSessionGuid) override;

  // Returns nonzero on success (original callers test the full EAX).
  int TrySendNetworkPacket(int nationId, void* packet, unsigned int byteCount);
  int TryReceiveNetworkPacketIntoResizableBuffer(DWORD* fromId, DWORD* toId, void** bufferHandle);
  bool OpenCurrentSessionDescriptionForJoin();
  bool DestroyPlayerAndStoreResult(DWORD idPlayer);
  bool InitializeDirectPlayForProviderGuidOrEnumerate(const GUID* providerGuid);
  BOOL OpenRuntimeSelectionSourceFromCurrentContext();
  bool CreatePlayerAndStoreResult(LPDPID idOut, LPSTR shortName);
  BOOL SetLocalPlayerDataAndStoreResult(LPVOID data, DWORD size);
  BOOL OpenRuntimeSelectionSourceWithUserChoice();
  BOOL RebuildRuntimeSelectionSource();
};
ASSERT_SIZE(TWNetSessionManager, 0xb4);
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR
