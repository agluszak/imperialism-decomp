#pragma once

#include "decomp_types.h"

#include "game/mfc.h"

// Real IDirectPlay2 from the DirectX 5 SDK <dplay.h> baked into the toolchain image
// (C:\dxsdk\include shadows the DirectX 1 copy in C:\msvc\include). The binary
// dispatches Receive at vtable +0x64 and Send at +0x68 — the IDirectPlay2 slot order
// (3 IUnknown + 22 methods before Receive); the DirectX 1 IDirectPlay had them at
// +0x54/+0x5c, which is how the interface generation was identified.
#include <dplay.h>
#include <dplobby.h>

class TView;
class TRadioTextCluster;

// One heap-owned entry in the DirectPlay runtime-selection list. The first four
// dwords are the payload returned by the selection dialog; the trailing CString is
// the displayed label (AppendRuntimeSelectionRecordEntry, 0x0047f8b0).
struct RuntimeSelectionRecord {
  GUID providerGuid;
  CString label;

  ~RuntimeSelectionRecord();
};

// WNetMgr.cpp owns a second, layout-identical selection record. Retail emits its
// CString-releasing destructor at 0x005e2850 rather than folding it with the
// DirectPlay.cpp record destructor at 0x0047f7f0.
struct WNetSelectionRecord {
  GUID providerGuid;
  CString label;

  ~WNetSelectionRecord();
};

// DirectPlay.cpp base state. The retail WNetMgr constructor first installs the base
// vtable at 0x0066f9c0, initializes +0x04/+0x08, constructs the derived CString at
// +0xa8, and finally installs the derived vtable at 0x0066f9f0.
IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
// VTABLE: IMPERIALISM 0x0066f9c0
class TDirectPlaySessionManagerBase {
public:
  TDirectPlaySessionManagerBase() : directPlayInterface04(0), directPlayLobby08(0) {}

  virtual BOOL OnEnumerateServiceProvider(LPGUID providerGuid, LPSTR providerName,
                                          DWORD majorVersion, DWORD minorVersion);
  virtual BOOL OnDirectPlayAssertion111(void* arg1, void* arg2, void* arg3, void* arg4);
  virtual BOOL OnEnumerateJoinableSession(const DPSESSIONDESC2* sessionDescription, DWORD* timeout,
                                          DWORD flags);
  virtual void InitializeSessionDescription();
  virtual void ResetSessionDescription();
  virtual BOOL GetRuntimeSelectionAuxStatus(void* value);
  BOOL ConnectDirectPlayFromLobbySettingsAndStoreResult(); // 0x47fbc0
  // DirectPlay DPESC_TIMEDOUT branch of the EnumSessions callback: while Ctrl is held,
  // extend the enumeration timeout by 500ms and return TRUE to keep enumerating.
  virtual BOOL ExtendEnumSessionsTimeoutWhileCtrlHeld(DWORD* timeoutMs);
  virtual BOOL SelectRuntimeProvider(GUID* providerGuid);
  virtual BOOL ShowJoinGameSelectionDialogAndCaptureChoice(GUID* selectedSessionGuid);

  // Reads a player's per-player data block, recording the HRESULT in lastErrorCode0c
  // and returning whether it succeeded. 0x4809d0.
  BOOL GetPlayerData(DPID playerId, void* buffer, DWORD* sizeInOut);
  BOOL CreateDirectPlayLobbyAndStoreResult(); // 0x0047fb80
  BOOL FindHostPlayerIdByEnumeration();       // 0x005e2980

  IDirectPlay2* directPlayInterface04;
  IDirectPlayLobbyA* directPlayLobby08;
  int lastErrorCode0c;
  DPSESSIONDESC2 sessionDescription10;
  int localPlayerId60;
  int broadcastPlayerId64;
  char joinGameSeed68[0x20];
  char runtimeSelectionSeed88[0x20];
};
ASSERT_SIZE(TDirectPlaySessionManagerBase, 0xa8);

// DirectPlay session manager from the original D:\Ambit\DirectPlay.cpp TU (assert helpers
// 0x47fb20/0x47fb50/0x480820 name it). Lives as a global object embedded at fixed address
// 0x006a5f60 (not a pointer-to-object); the original loads `MOV ECX, 0x6a5f60` directly.
// Windows DirectPlay session manager; the Mac build used the unrelated NetSprocket API.
// VTABLE: IMPERIALISM 0x0066f9f0
class TWNetSessionManager : public TDirectPlaySessionManagerBase {
public:
  CString joinGamePlayerNameA8;
  int joinGamePlayerDataTagAC;
  TRadioTextCluster* activeProtocolControlB0;

  TWNetSessionManager();
  // Non-virtual on purpose: the original derived vtable at 0x66f9f0 has exactly the
  // base's 9 slots (first null at slot 9), and the only call site is the direct
  // atexit teardown of the fixed global at 0x6a5f60 (0x5e2a00). A virtual dtor here
  // emitted a phantom 10th slot the original lacks (the vtable sweep's oversize
  // warning).
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
  // IDirectPlay2::DestroyPlayer + result capture (no interface null-check, unlike
  // TrySendNetworkPacket). Returns SUCCEEDED(result) in AL.
  unsigned char DestroyPlayerAndStoreResult(DWORD idPlayer);
  // Free the runtime selection entries and release the DirectPlay interfaces.
  void ResetRuntimeSelectionRecordBuffer(); // 0x00480400
  // If providerGuid is null and a session is already open (directPlayInterface04 !=
  // 0), no-op success. Otherwise closes any open session, then either creates a
  // fresh IDirectPlay bound to providerGuid (DirectPlayCreate, ordinal 1 of
  // DPLAYX.DLL) or, when providerGuid is null, enumerates providers
  // (DirectPlayEnumerateA, ordinal 2) through this object's virtual provider callback.
  // Either way the resulting IDirectPlay is QueryInterface'd up to
  // IDirectPlay2 into directPlayInterface04 and the runtime-selection list is reset.
  bool InitializeDirectPlayForProviderGuidOrEnumerate(const GUID* providerGuid); // 0x47fe50
  // Reopens the session with provider enumeration
  // (InitializeDirectPlayForProviderGuidOrEnumerate(null)),
  // then rebuilds sessionDescription10, lets the derived slot populate its application
  // identity, and opens it as a newly created DirectPlay session.
  BOOL OpenRuntimeSelectionSourceFromCurrentContext(); // 0x480030
  // IDirectPlay2::CreatePlayer wrapper: builds a DPNAME from shortName (dwSize=16,
  // dwFlags=0, lpszShortNameA=shortName, lpszLongNameA=0) and stores the HRESULT in
  // lastErrorCode0c. Returns SUCCEEDED(result).
  char CreatePlayerAndStoreResult(LPDPID idOut, LPSTR shortName); // 0x47fcb0
  // IDirectPlay2::SetPlayerData wrapper for the local player (localPlayerId60),
  // dwFlags=DPSET_LOCAL(2). Stores the HRESULT in lastErrorCode0c and returns
  // SUCCEEDED(result).
  BOOL SetLocalPlayerDataAndStoreResult(LPVOID data, DWORD size); // 0x480990
  // Presents the "choose a session to join" flow (DirectPlayCreate(NULL),
  // AfxMessageBox-backed progress UI and EnumSessions, and leaves directPlayInterface04
  // bound to the chosen session on success. The callback-table dispatch and
  // AfxGetMainWnd()/message-box progress-UI plumbing aren't modeled yet, so this
  // remains structurally incomplete; always reports failure until that's done.
  BOOL OpenRuntimeSelectionSourceWithUserChoice(); // 0x480150
  // Clears g_RuntimeSelectionRecords006a15e0 and re-issues DirectPlayEnumerateA
  // (ordinal 2) via ForwardEnumSessionToCallbackTable/this, storing the HRESULT in
  // lastErrorCode0c. Returns SUCCEEDED(result). Ghidra-verified: takes no explicit
  // stack argument (bare RET, no ret-n cleanup) -- TNetMgr's caller does not forward
  // its own `provider` here.
  BOOL RebuildRuntimeSelectionSource(); // 0x47fd90
};
ASSERT_SIZE(TWNetSessionManager, 0xb4);
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR
