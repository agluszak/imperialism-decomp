#pragma once

#include "decomp_types.h"

#include "game/mfc.h"

// Real IDirectPlay2 from the DirectX 5 SDK <dplay.h> baked into the toolchain image
// (C:\dxsdk\include shadows the DirectX 1 copy in C:\msvc\include). The binary
// dispatches Receive at vtable +0x64 and Send at +0x68 — the IDirectPlay2 slot order
// (3 IUnknown + 22 methods before Receive); the DirectX 1 IDirectPlay had them at
// +0x54/+0x5c, which is how the interface generation was identified.
#include <dplay.h>

// One heap-owned entry in the DirectPlay runtime-selection list. The first four
// dwords are the payload returned by the selection dialog; the trailing CString is
// the displayed label (AppendRuntimeSelectionRecordEntry, 0x0047f8b0).
struct RuntimeSelectionRecord {
  int payload[4];
  CString label;

  ~RuntimeSelectionRecord();
};

// DirectPlay session manager from the original D:\Ambit\DirectPlay.cpp TU (assert helpers
// 0x47fb20/0x47fb50/0x480820 name it). Lives as a global object embedded at fixed address
// 0x006a5f60 (not a pointer-to-object); the original loads `MOV ECX, 0x6a5f60` directly.
// The class name is provisional (no Mac counterpart — the Mac build used NetSprocket).
// Raw two-slot callback table used only by the DirectPlayEnumerateA path in
// OpenRuntimeSelectionSourceWithOptionalSeed: slot 0 receives each enumerated
// service provider (matches the LPDPENUMDPCALLBACKA shape: GUID*, name, majorVer,
// minorVer), slot 7 (byte 0x1c) runs once enumeration completes. No writer of this
// table is present anywhere in the retail binary (the field is always null in
// static data and no ctor/init path sets it), so the enumerate-without-a-seed
// branch that reads it is dead code in the shipped game; ported as-is rather than
// invented, since the original never guards the null read either.
struct DirectPlayEnumerationCallbackTable {
  BOOL(FAR PASCAL* onEnumSession)(LPGUID sessionGuid, LPSTR sessionName, DWORD majorVersion,
                                  DWORD minorVersion);
  void* unusedSlots1To6[6];
  int(FAR PASCAL* onEnumerationComplete)(void* resultBuffer);
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
  // Drop g_RuntimeSelectionRecords006a15e0's contents and free its backing array
  // (shared tail of ResetRuntimeSelectionRecordBuffer and
  // OpenRuntimeSelectionSourceWithOptionalSeed's success paths).
  void ClearRuntimeSelectionRecordArray();
  // If sessionEntry is null and a session is already open (directPlayInterface04 !=
  // 0), no-op success. Otherwise closes any open session, then either creates a
  // fresh IDirectPlay bound to sessionEntry's GUID (DirectPlayCreate, ordinal 1 of
  // DPLAYX.DLL) or, when sessionEntry is null, enumerates providers
  // (DirectPlayEnumerateA, ordinal 2) via enumCallbackTable00 -- see that field's
  // comment. Either way the resulting IDirectPlay is QueryInterface'd up to
  // IDirectPlay2 into directPlayInterface04 and the runtime-selection list is reset.
  unsigned char OpenRuntimeSelectionSourceWithOptionalSeed(const GUID* sessionEntry,
                                                            int flag); // 0x47fe50
};

// 0x4804c0: adds 500 to *value and returns 1 when Ctrl is held, else 0.
int __stdcall ApplyCtrlScrollAccelerationToListStep(int* value);
