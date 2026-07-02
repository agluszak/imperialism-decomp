#include "game/TWNetSessionManager.h"

// FUNCTION: IMPERIALISM 0x0047fd30
unsigned char TWNetSessionManager::DestroyPlayerAndStoreResult(DWORD idPlayer) {
  long destroyResult = this->directPlayInterface04->DestroyPlayer(idPlayer);
  this->lastErrorCode0c = destroyResult;
  return destroyResult >= 0;
}

// FUNCTION: IMPERIALISM 0x00480850
int TWNetSessionManager::TrySendNetworkPacket(int nationId, void* packet, unsigned int byteCount) {
  IDirectPlay2* directPlay = this->directPlayInterface04;
  if (directPlay == 0) {
    return 0;
  }
  long sendResult = directPlay->Send(this->localPlayerId60, nationId, 1, packet, byteCount);
  this->lastErrorCode0c = sendResult;
  return sendResult >= 0;
}

// Pulls the next pending DirectPlay message into *bufferHandle, growing the GlobalAlloc
// buffer until IDirectPlay2::Receive stops reporting DPERR_BUFFERTOOSMALL.
// DPERR_NOMESSAGES ends the loop without a message.
// FUNCTION: IMPERIALISM 0x004808a0
int TWNetSessionManager::TryReceiveNetworkPacketIntoResizableBuffer(DWORD* fromId, DWORD* toId,
                                                                    void** bufferHandle) {
  IDirectPlay2* directPlay = this->directPlayInterface04;
  if (directPlay == 0) {
    return 1;
  }
  *bufferHandle = 0;
  DWORD neededSize = 0;
  long receiveResult;
  do {
    if (neededSize != 0) {
      HGLOBAL grownBuffer;
      if (*bufferHandle == 0) {
        grownBuffer = GlobalAlloc(0, neededSize);
      } else {
        grownBuffer = GlobalReAlloc(*bufferHandle, neededSize, 0);
      }
      *bufferHandle = grownBuffer;
    }
    receiveResult = directPlay->Receive(fromId, toId, 1, *bufferHandle, &neededSize);
    this->lastErrorCode0c = receiveResult;
  } while (receiveResult != DPERR_NOMESSAGES &&
           (*bufferHandle == 0 || receiveResult == DPERR_BUFFERTOOSMALL));
  if (receiveResult < 0 && receiveResult != DPERR_NOMESSAGES) {
    GlobalFree(*bufferHandle);
    *bufferHandle = 0;
    return 0;
  }
  return receiveResult >= 0;
}
