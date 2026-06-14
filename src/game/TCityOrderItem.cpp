#include "game/TCityOrderItem.h"

#include "game/CRuntimeClass.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x004b5180
void TCityOrderItem::Produce(void* orderSheet) {
  undefined4* cursor = static_cast<undefined4*>(orderSheet);
  int remaining = 0x1e;
  while (remaining != 0) {
    *cursor = 0;
    cursor = cursor + 1;
    remaining = remaining + -1;
  }
  *reinterpret_cast<short*>(cursor) = 0;
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(orderSheet) + 0x7a) = 0;
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(orderSheet) + 0x7c) = 0;
}

CRuntimeClass* TCityOrderItem::GetRuntimeClass() {
  return CObject::GetRuntimeClass();
}

void TCityOrderItem::Serialize(CArchive* ar) {
  CObject::Serialize(ar);
}

void TCityOrderItem::AssertValidOrSlot0c() {
  CObject::AssertValidOrSlot0c();
}

void TCityOrderItem::DumpOrSlot10(int unused) {
  CObject::DumpOrSlot10(unused);
}
