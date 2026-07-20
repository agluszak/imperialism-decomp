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

// One heap-owned entry in the DirectPlay runtime-selection list. The first four
// dwords are the payload returned by the selection dialog; the trailing CString is
// the displayed label (AppendRuntimeSelectionRecordEntry, 0x0047f8b0).
struct RuntimeSelectionRecord {
  int payload[4];
  CString label;

  ~RuntimeSelectionRecord();
};

// Raw callback/dispatch table used by two DirectPlay session-discovery paths:
// OpenRuntimeSelectionSourceWithOptionalSeed's DirectPlayEnumerateA branch calls
// slot 0 (LPDPENUMDPCALLBACKA shape: GUID*, name, majorVer, minorVer) per
// enumerated service provider and slot 7 (byte 0x1c) once done;
// OpenRuntimeSelectionSourceWithUserChoice dereferences further slots (at least
// byte 0x10 and 0x20) unconditionally. No writer of this table has been located
// yet (static value is null, no ctor/init path found) despite
// OpenRuntimeSelectionSourceWithUserChoice being the primary interactive
// host/join path, not obviously dead code -- flagged as an open class-recovery
// question rather than asserted either way.
struct DirectPlayEnumerationCallbackTable {
  BOOL(FAR PASCAL* onEnumSession)(LPGUID sessionGuid, LPSTR sessionName, DWORD majorVersion,
                                  DWORD minorVersion);
  void* unusedSlots1To2[2];
  void* slot4;
  void* unusedSlot5;
  void* slot6;
  int(FAR PASCAL* onEnumerationComplete)(void* resultBuffer);
  void* slot8;
};

// DirectPlay session manager from the original D:\Ambit\DirectPlay.cpp TU (assert helpers
// 0x47fb20/0x47fb50/0x480820 name it). Lives as a global object embedded at fixed address
// 0x006a5f60 (not a pointer-to-object); the original loads `MOV ECX, 0x6a5f60` directly.
// The class name is provisional (no Mac counterpart — the Mac build used NetSprocket).
class TWNetSessionManager {
public:
  DirectPlayEnumerationCallbackTable* enumCallbackTable00;
  IDirectPlay2* directPlayInterface04;
  IUnknown* directPlayLobby08;
  int lastErrorCode0c;
  unsigned char pad10[0x60 - 0x10];
  int localPlayerId60;

  // Returns nonzero on success (original callers test the full EAX).
  int TrySendNetworkPacket(int nationId, void* packet, unsigned int byteCount);
  int TryReceiveNetworkPacketIntoResizableBuffer(DWORD* fromId, DWORD* toId, void** bufferHandle);
  // IDirectPlay2::DestroyPlayer + result capture (no interface null-check, unlike
  // TrySendNetworkPacket). Returns SUCCEEDED(result) in AL.
  unsigned char DestroyPlayerAndStoreResult(DWORD idPlayer);
  // Free the runtime selection entries and release the DirectPlay interfaces.
  void ResetRuntimeSelectionRecordBuffer(); // 0x00480400
  // If sessionEntry is null and a session is already open (directPlayInterface04 !=
  // 0), no-op success. Otherwise closes any open session, then either creates a
  // fresh IDirectPlay bound to sessionEntry's GUID (DirectPlayCreate, ordinal 1 of
  // DPLAYX.DLL) or, when sessionEntry is null, enumerates providers
  // (DirectPlayEnumerateA, ordinal 2) via enumCallbackTable00 -- see that field's
  // comment. Either way the resulting IDirectPlay is QueryInterface'd up to
  // IDirectPlay2 into directPlayInterface04 and the runtime-selection list is reset.
  unsigned char OpenRuntimeSelectionSourceWithOptionalSeed(const GUID* sessionEntry,
                                                           int flag); // 0x47fe50
  // IDirectPlay2::CreatePlayer wrapper: builds a DPNAME from shortName (dwSize=16,
  // dwFlags=0, lpszShortNameA=shortName, lpszLongNameA=0) and stores the HRESULT in
  // lastErrorCode0c. Returns SUCCEEDED(result).
  unsigned char CreatePlayerAndStoreResult(LPDPID idOut, LPSTR shortName); // 0x47fcb0
  // IDirectPlay2::SetPlayerData wrapper for the local player (localPlayerId60),
  // dwFlags=DPSET_LOCAL(2). Stores the HRESULT in lastErrorCode0c and returns
  // SUCCEEDED(result).
  unsigned char SetLocalPlayerDataAndStoreResult(LPVOID data, DWORD size); // 0x480990
  // Presents the "choose a session to join" flow (DirectPlayCreate(NULL),
  // AfxMessageBox-backed progress UI, EnumSessions, and dispatch through
  // enumCallbackTable00 -- see that field's comment) and leaves directPlayInterface04
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

// 0x4804c0: adds 500 to *value and returns 1 when Ctrl is held, else 0.
int __stdcall ApplyCtrlScrollAccelerationToListStep(int* value);
