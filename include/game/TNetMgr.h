#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

struct NetMessage;

// Global turn-event queue manager handle (ConstructGlobalTurnEventQueueManager @ 0x005e33e0
// only stores vptr 0x0066fa20 on a 4-byte heap block). Plain TObject derivative — no extra
// bases. The adjacent vtables at 0x0066fa50/0x0066fa68 are NOT TNetMgr slots: they are the
// WNetMgr.cpp TU's twin copies of the CList<void*,void*> / CArray<void*,void*> template
// vtables for the file-scope statics g_WNetPendingPacketList006a5f40 /
// g_WNetSerializedPtrArray{A,B} (ctor/dtor evidence 0x5e4540/0x5e4580, 0x5e4780/0x5e47b0;
// Serialize instantiations 0x5e4610/0x5e4830).
// VTABLE: IMPERIALISM 0x0066fa20
class TNetMgr : public TObject {
public:
  DECLARE_DYNCREATE(TNetMgr)
  virtual ~TNetMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x5e3470
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a null (0x00000000)
  // slot 0x0b null (0x00000000)

  TNetMgr();

  // Queue the message for the local player and/or send it over DirectPlay
  // (message->toNetworkId == -1 broadcasts). `this` carries no state — the queue and
  // session-manager state are file-scope globals of the original WNetMgr.cpp TU.
  // Mac oracle: TNetMgr::Send(NSpMessageHeader*, unsigned char).
  unsigned char Send(NetMessage* message, unsigned char queueOnly);

  // Map a DirectPlay error HRESULT to detail text and pose the localized error dialog.
  // Mac oracle: TNetMgr::HandleError(int). Asserts with D:\Ambit\WNetMgr.cpp line 451.
  void HandleError(int errorCode);

  // Placement ctor on a 4-byte heap block (Ghidra: ConstructGlobalTurnEventQueueManager @
  // 0x005e33e0).
  static TNetMgr* ConstructGlobalTurnEventQueueManager(TNetMgr* storage);
};

// === BEGIN GENERATED (TNetMgr) — refreshed by `just gen-class TNetMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066fa20 (23 slots), object size 0x04, base TObject
//   slot 0x00  byte 0x00  0x005e33c0  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x005e3400  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x005e3470  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x00000000  null      (null)
//   slot 0x0b  byte 0x2c  0x00000000  null      (null)
// bytes 0x30..0x5b of the original blob are the separate CList<void*,void*> (0x66fa50)
// and CArray<void*,void*> (0x66fa68) template vtables of the WNetMgr.cpp statics —
// hand-corrected here because recover-class merged them by adjacency (gen-class dormant).
// object size 0x04 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TNetMgr) ===
