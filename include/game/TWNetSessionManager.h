#pragma once

#include "decomp_types.h"

#include "game/mfc.h"

// Faithful IDirectPlay2 vtable declaration (DirectX 3 dplay.h). The toolchain only ships
// the DirectX 1 <dplay.h>, whose IDirectPlay Receive/Send sit at vtable +0x54/+0x5c —
// the binary dispatches Receive at +0x64 and Send at +0x68, which is exactly the
// IDirectPlay2 slot order below (3 IUnknown + 22 methods before Receive). Only
// Receive/Send are called by game code; the other slots exist to pin the layout.
struct IDirectPlay2Compat {
  virtual long __stdcall QueryInterface(void* riid, void** ppvObj) = 0;
  virtual unsigned long __stdcall AddRef() = 0;
  virtual unsigned long __stdcall Release() = 0;
  virtual long __stdcall AddPlayerToGroup(DWORD idGroup, DWORD idPlayer) = 0;
  virtual long __stdcall Close() = 0;
  virtual long __stdcall CreateGroup(DWORD* lpidGroup, void* lpGroupName, void* lpData,
                                     DWORD dwDataSize, DWORD dwFlags) = 0;
  virtual long __stdcall CreatePlayer(DWORD* lpidPlayer, void* lpPlayerName, void* hEvent,
                                      void* lpData, DWORD dwDataSize, DWORD dwFlags) = 0;
  virtual long __stdcall DeletePlayerFromGroup(DWORD idGroup, DWORD idPlayer) = 0;
  virtual long __stdcall DestroyGroup(DWORD idGroup) = 0;
  virtual long __stdcall DestroyPlayer(DWORD idPlayer) = 0;
  virtual long __stdcall EnumGroupPlayers(DWORD idGroup, void* lpguidInstance,
                                          void* lpEnumPlayersCallback2, void* lpContext,
                                          DWORD dwFlags) = 0;
  virtual long __stdcall EnumGroups(void* lpguidInstance, void* lpEnumPlayersCallback2,
                                    void* lpContext, DWORD dwFlags) = 0;
  virtual long __stdcall EnumPlayers(void* lpguidInstance, void* lpEnumPlayersCallback2,
                                     void* lpContext, DWORD dwFlags) = 0;
  virtual long __stdcall EnumSessions(void* lpsd, DWORD dwTimeout, void* lpEnumSessionsCallback2,
                                      void* lpContext, DWORD dwFlags) = 0;
  virtual long __stdcall GetCaps(void* lpDPCaps, DWORD dwFlags) = 0;
  virtual long __stdcall GetGroupData(DWORD idGroup, void* lpData, DWORD* lpdwDataSize,
                                      DWORD dwFlags) = 0;
  virtual long __stdcall GetGroupName(DWORD idGroup, void* lpData, DWORD* lpdwDataSize) = 0;
  virtual long __stdcall GetMessageCount(DWORD idPlayer, DWORD* lpdwCount) = 0;
  virtual long __stdcall GetPlayerAddress(DWORD idPlayer, void* lpAddress,
                                          DWORD* lpdwAddressSize) = 0;
  virtual long __stdcall GetPlayerCaps(DWORD idPlayer, void* lpPlayerCaps, DWORD dwFlags) = 0;
  virtual long __stdcall GetPlayerData(DWORD idPlayer, void* lpData, DWORD* lpdwDataSize,
                                       DWORD dwFlags) = 0;
  virtual long __stdcall GetPlayerName(DWORD idPlayer, void* lpData, DWORD* lpdwDataSize) = 0;
  virtual long __stdcall GetSessionDesc(void* lpData, DWORD* lpdwDataSize) = 0;
  virtual long __stdcall Initialize(void* lpGUID) = 0;
  virtual long __stdcall Open(void* lpsd, DWORD dwFlags) = 0;
  virtual long __stdcall Receive(DWORD* lpidFrom, DWORD* lpidTo, DWORD dwFlags, void* lpData,
                                 DWORD* lpdwDataSize) = 0; // vtable +0x64
  virtual long __stdcall Send(DWORD idFrom, DWORD idTo, DWORD dwFlags, void* lpData,
                              DWORD dwDataSize) = 0; // vtable +0x68
};

// DirectPlay session manager from the original D:\Ambit\DirectPlay.cpp TU (assert helpers
// 0x47fb20/0x47fb50/0x480820 name it). Lives as a global object embedded at fixed address
// 0x006a5f60 (not a pointer-to-object); the original loads `MOV ECX, 0x6a5f60` directly.
// The class name is provisional (no Mac counterpart — the Mac build used NetSprocket).
class TWNetSessionManager {
public:
  unsigned char pad00[4];
  IDirectPlay2Compat* directPlayInterface04;
  unsigned char pad08[4];
  int lastErrorCode0c;
  unsigned char pad10[0x60 - 0x10];
  int localPlayerId60;

  // Returns nonzero on success (original callers test the full EAX).
  int TrySendNetworkPacket(int nationId, void* packet, unsigned int byteCount);
  int TryReceiveNetworkPacketIntoResizableBuffer(DWORD* fromId, DWORD* toId, void** bufferHandle);
};
