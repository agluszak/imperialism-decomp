#include "game/TWNetSessionManager.h"

// FUNCTION: IMPERIALISM 0x00480850
int TWNetSessionManager::TrySendNetworkPacket(int nationId, void* packet, unsigned int byteCount) {
  IDirectPlay2Compat* directPlay = this->directPlayInterface04;
  if (directPlay == 0) {
    return 0;
  }
  long sendResult = directPlay->Send(this->localPlayerId60, nationId, 1, packet, byteCount);
  this->lastErrorCode0c = sendResult;
  return sendResult >= 0;
}

// Pulls the next pending DirectPlay message into *bufferHandle, growing the GlobalAlloc
// buffer until IDirectPlay2::Receive stops reporting DPERR_BUFFERTOOSMALL (-0x7788ffe2).
// DPERR_NOMESSAGES (-0x7788ff42) ends the loop without a message.
// FUNCTION: IMPERIALISM 0x004808a0
int TWNetSessionManager::TryReceiveNetworkPacketIntoResizableBuffer(DWORD* fromId, DWORD* toId,
                                                                    void** bufferHandle) {
  IDirectPlay2Compat* directPlay = this->directPlayInterface04;
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
  } while (receiveResult != -0x7788ff42 && (*bufferHandle == 0 || receiveResult == -0x7788ffe2));
  if (receiveResult < 0 && receiveResult != -0x7788ff42) {
    GlobalFree(*bufferHandle);
    *bufferHandle = 0;
    return 0;
  }
  return receiveResult >= 0;
}
