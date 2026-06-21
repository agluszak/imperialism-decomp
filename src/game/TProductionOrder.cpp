#include "game/TProductionOrder.h"

CRuntimeClass* TProductionOrder::GetRuntimeClass() const { return 0; }

TProductionOrder::~TProductionOrder() {}

undefined TProductionOrder::InitializeBasicCityOrderContext(int param_1, undefined2 param_2) { return 0; }

void TProductionOrder::WriteTo(TStream* stream) {}

void TProductionOrder::ReadFrom(TStream* stream) {}

undefined TProductionOrder::OrphanLeaf_NoCall_Ins02_004b50e0() { return 0; }

undefined TProductionOrder::OrphanCallChain_C1_I16_004b5100(short param_1) { return 0; }

undefined TProductionOrder::ResetCityOrderItemDerivedStateNoop() { return 0; }

undefined TProductionOrder::OrphanRetStub_004b5160() { return 0; }

// Slot 0x3c (Mac: Produce) — clears the OrderSheet working buffers. The body lives
// in TProductionOrder's own vtable region; TCityOrderItem (TCapacityOrder's parallel
// chain) shares the same slot but cannot own the address.
// FUNCTION: IMPERIALISM 0x004b5180
undefined TProductionOrder::InitializeCityOrderItemWorkingBuffers(undefined4* param_1) {
  undefined4* cursor = param_1;
  int remaining = 0x1e;
  while (remaining != 0) {
    *cursor = 0;
    cursor = cursor + 1;
    remaining = remaining + -1;
  }
  *reinterpret_cast<short*>(cursor) = 0;
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(param_1) + 0x7a) = 0;
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(param_1) + 0x7c) = 0;
  return 0;
}

undefined TProductionOrder::CreateTItemOrderInstance() { return 0; }
