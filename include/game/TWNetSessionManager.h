#pragma once

#include "decomp_types.h"

#include "game/mfc.h"

// Real IDirectPlay2 from the DirectX 5 SDK <dplay.h> baked into the toolchain image
// (C:\dxsdk\include shadows the DirectX 1 copy in C:\msvc\include). The binary
// dispatches Receive at vtable +0x64 and Send at +0x68 — the IDirectPlay2 slot order
// (3 IUnknown + 22 methods before Receive); the DirectX 1 IDirectPlay had them at
// +0x54/+0x5c, which is how the interface generation was identified.
#include <dplay.h>

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
  virtual BOOL ApplyCtrlScrollAcceleration(int* value);
  virtual BOOL SelectRuntimeProvider(GUID* providerGuid);
  virtual BOOL ShowJoinGameSelectionDialogAndCaptureChoice(GUID* selectedSessionGuid);

  // Reads a player's per-player data block, recording the HRESULT in lastErrorCode0c
  // and returning whether it succeeded. 0x4809d0.
  BOOL GetPlayerData(DPID playerId, void* buffer, DWORD* sizeInOut);

  IDirectPlay2* directPlayInterface04;
  IUnknown* directPlayLobby08;
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
// The class name is provisional (no Mac counterpart — the Mac build used NetSprocket).
// VTABLE: IMPERIALISM 0x0066f9f0
class TWNetSessionManager : public TDirectPlaySessionManagerBase {
public:
  CString joinGamePlayerNameA8;
  int joinGamePlayerDataTagAC;
  TRadioTextCluster* activeProtocolControlB0;

  TWNetSessionManager();
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
  // If sessionEntry is null and a session is already open (directPlayInterface04 !=
  // 0), no-op success. Otherwise closes any open session, then either creates a
  // fresh IDirectPlay bound to sessionEntry's GUID (DirectPlayCreate, ordinal 1 of
  // DPLAYX.DLL) or, when sessionEntry is null, enumerates providers
  // (DirectPlayEnumerateA, ordinal 2) through this object's virtual provider callback.
  // Either way the resulting IDirectPlay is QueryInterface'd up to
  // IDirectPlay2 into directPlayInterface04 and the runtime-selection list is reset.
  unsigned char OpenRuntimeSelectionSourceWithOptionalSeed(const GUID* sessionEntry); // 0x47fe50
  // Reopens the session with no seed (OpenRuntimeSelectionSourceWithOptionalSeed(null,0)),
  // then rebuilds sessionDescription10, lets the derived slot populate its application
  // identity, and opens it as a newly created DirectPlay session.
  unsigned char OpenRuntimeSelectionSourceFromCurrentContext(); // 0x480030
  // IDirectPlay2::CreatePlayer wrapper: builds a DPNAME from shortName (dwSize=16,
  // dwFlags=0, lpszShortNameA=shortName, lpszLongNameA=0) and stores the HRESULT in
  // lastErrorCode0c. Returns SUCCEEDED(result).
  unsigned char CreatePlayerAndStoreResult(LPDPID idOut, LPSTR shortName); // 0x47fcb0
  // IDirectPlay2::SetPlayerData wrapper for the local player (localPlayerId60),
  // dwFlags=DPSET_LOCAL(2). Stores the HRESULT in lastErrorCode0c and returns
  // SUCCEEDED(result).
  unsigned char SetLocalPlayerDataAndStoreResult(LPVOID data, DWORD size); // 0x480990
  // Presents the "choose a session to join" flow (DirectPlayCreate(NULL),
  // AfxMessageBox-backed progress UI and EnumSessions, and leaves directPlayInterface04
  // bound to the chosen session on success. The callback-table dispatch and
  // AfxGetMainWnd()/message-box progress-UI plumbing aren't modeled yet, so this
  // remains structurally incomplete; always reports failure until that's done.
  unsigned char OpenRuntimeSelectionSourceWithUserChoice(); // 0x480150
  // Clears g_RuntimeSelectionRecords006a15e0 and re-issues DirectPlayEnumerateA
  // (ordinal 2) via ForwardEnumSessionToCallbackTable/this, storing the HRESULT in
  // lastErrorCode0c. Returns SUCCEEDED(result). Ghidra-verified: takes no explicit
  // stack argument (bare RET, no ret-n cleanup) -- TNetMgr's caller does not forward
  // its own `provider` here.
  unsigned char RebuildRuntimeSelectionSource(); // 0x47fd90
};
ASSERT_SIZE(TWNetSessionManager, 0xb4);
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR
