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

// WNetMgr.cpp free helpers over the file-scope session state.
// Returns the local session id global 0x6a5fc0.
int GetSessionActiveNationId(); // 0x5e4280
// Destroys the DirectPlay player when `nationId` is the local session id (name kept
// from Ghidra; the body destroys, it does not notify).
void __stdcall NotifyIfNationMatchesSessionActiveNation(int nationId); // 0x5e42c0

