#include "game/TExpansionOrder.h"

#include "game/TStream.h"

// SYNTHETIC: IMPERIALISM 0x004b8f50
// TExpansionOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b8f80
// TExpansionOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TExpansionOrder, TItemOrder)

TExpansionOrder::TExpansionOrder() {}

// SYNTHETIC: IMPERIALISM 0x004b8fc0
// TExpansionOrder::`scalar deleting destructor'
TExpansionOrder::~TExpansionOrder() {}

// FUNCTION: IMPERIALISM 0x004b9010
undefined TExpansionOrder::ExpansionOrderSlot12(int param_1, undefined2 param_2, undefined2 param_3,
                                                undefined2 param_4, undefined2 param_5) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b9090
undefined TExpansionOrder::CommitIfPending() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b91f0
short TExpansionOrder::MaxOrder() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b9260
bool TExpansionOrder::SetQuantity(short param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b9340
void SwapFirstTwoBytesInBuffer(unsigned char* buffer) {
  unsigned char tmp = buffer[0];
  buffer[0] = buffer[1];
  buffer[1] = tmp;
}

// FUNCTION: IMPERIALISM 0x004b9360
void TExpansionOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  this->InitializeCityOrderItemWorkingBuffers(orderSheet);
  orderSheet->ForResourceCode(this->primaryInputResourceId) = quantity;
  if (orderSheet->ForResourceCode(this->primaryInputResourceId) < 0) {
    orderSheet->ForResourceCode(this->primaryInputResourceId) = 0;
  }
  orderSheet->ForResourceCode(this->secondaryInputResourceId) = quantity;
  if (orderSheet->ForResourceCode(this->secondaryInputResourceId) < 0) {
    orderSheet->ForResourceCode(this->secondaryInputResourceId) = 0;
  }
}

// Writes a `count`-element array of shorts to the stream in swapped byte order: each
// word is copied into a 2-byte scratch, byte-swapped via SwapFirstTwoBytesInBuffer
// (inlined), and pushed through the stream's WriteBytesSlot78 primitive (vtable slot
// 0x78). Callers: TCity::WriteTo (0x4b38b6) and SerializeThreeWordPlanesToOutputCallback
// (0x4ef493).
// FUNCTION: IMPERIALISM 0x004b94a0
void WriteWordArrayToOutputCallbackLE(TStream* stream, short* words, int count) {
  for (; count > 0; --count) {
    unsigned short buffer = static_cast<unsigned short>(*words);
    // SwapFirstTwoBytesInBuffer inlined at this site in the original.
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&buffer);
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
    stream->WriteBytesSlot78(&buffer, 2);
    ++words;
  }
}
