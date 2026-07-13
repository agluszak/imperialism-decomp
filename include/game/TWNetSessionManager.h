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
class TWNetSessionManager {
public:
  unsigned char pad00[4];
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
};
