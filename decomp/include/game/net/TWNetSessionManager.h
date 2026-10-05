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
  TDirectPlaySessionManagerBase() : directPlayInterface04(0), directPlayLobby(0) {}
  ~TDirectPlaySessionManagerBase();

  virtual BOOL OnEnumerateServiceProvider(LPGUID providerGuid, LPSTR providerName,
                                          DWORD majorVersion, DWORD minorVersion);
  virtual BOOL OnDirectPlayAssertion111(void* arg1, void* arg2, void* arg3, void* arg4);
  virtual BOOL OnEnumerateJoinableSession(const DPSESSIONDESC2* sessionDescription, DWORD* timeout,
                                          DWORD flags);
  virtual void InitializeSessionDescription();
  virtual void ResetSessionDescription();
  virtual BOOL GetRuntimeSelectionAuxStatus(void* value);
  BOOL ConnectDirectPlayFromLobbySettingsAndStoreResult(); // 0x47fbc0
  virtual BOOL ExtendEnumSessionsTimeoutWhileCtrlHeld(DWORD* timeoutMs);
  virtual BOOL SelectRuntimeProvider(GUID* providerGuid);
  virtual BOOL ShowJoinGameSelectionDialogAndCaptureChoice(GUID* selectedSessionGuid);

  BOOL GetPlayerData(DPID playerId, void* buffer, DWORD* sizeInOut);
  BOOL CreateDirectPlayLobbyAndStoreResult(); // 0x0047fb80
  BOOL FindHostPlayerIdByEnumeration();       // 0x005e2980
  // Free the runtime selection entries and release the DirectPlay interfaces.
  void ResetRuntimeSelectionRecordBuffer(); // 0x00480400

  IDirectPlay2* directPlayInterface04;
  IDirectPlayLobbyA* directPlayLobby;
  int lastErrorCode0c;
  DPSESSIONDESC2 sessionDescription10;
  int localPlayerId60;
  int broadcastPlayerId64;
  char joinGameSeed68[0x20];
  char runtimeSelectionSeed88[0x20];
};
ASSERT_SIZE(TDirectPlaySessionManagerBase, 0xa8);

// VTABLE: IMPERIALISM 0x0066f9f0
class TWNetSessionManager : public TDirectPlaySessionManagerBase {
public:
  CString joinGamePlayerNameA8;
  int joinGamePlayerDataTag;
  TRadioTextCluster* activeProtocolControl;

  TWNetSessionManager();
  ~TWNetSessionManager(); // 0x005e2a20 — frees the serialized-record scratch arrays
  virtual BOOL OnEnumerateServiceProvider(LPGUID providerGuid, LPSTR providerName,
                                          DWORD majorVersion, DWORD minorVersion) override;
  virtual BOOL OnEnumerateJoinableSession(const DPSESSIONDESC2* sessionDescription, DWORD* timeout,
                                          DWORD flags) override;
  virtual void InitializeSessionDescription() override;
  virtual void ResetSessionDescription() override;
  virtual BOOL ShowJoinGameSelectionDialogAndCaptureChoice(
      GUID* selectedSessionGuid) override; // slot 0x08 0x5e30c0

  // Returns nonzero on success (original callers test the full EAX).
  int TrySendNetworkPacket(int nationId, void* packet, unsigned int byteCount);
  int TryReceiveNetworkPacketIntoResizableBuffer(DWORD* fromId, DWORD* toId, void** bufferHandle);
  unsigned char OpenCurrentSessionDescriptionForJoin(); // 0x4803d0
  unsigned char DestroyPlayerAndStoreResult(DWORD idPlayer);
  bool InitializeDirectPlayForProviderGuidOrEnumerate(const GUID* providerGuid); // 0x47fe50
  BOOL OpenRuntimeSelectionSourceFromCurrentContext(); // 0x480030
  char CreatePlayerAndStoreResult(LPDPID idOut, LPSTR shortName); // 0x47fcb0
  BOOL SetLocalPlayerDataAndStoreResult(LPVOID data, DWORD size); // 0x480990
  BOOL OpenRuntimeSelectionSourceWithUserChoice(); // 0x480150
  BOOL RebuildRuntimeSelectionSource(); // 0x47fd90
};
ASSERT_SIZE(TWNetSessionManager, 0xb4);
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR
