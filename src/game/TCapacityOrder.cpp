#include "game/TCapacityOrder.h"

#include "game/CRuntimeClass.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// GLOBAL: IMPERIALISM 0x0064f440
CRuntimeClass g_pClassDescTCapacityOrder = {0};
// GLOBAL: IMPERIALISM 0x00695b50
char g_industryActionCostWeightResCode09;
// GLOBAL: IMPERIALISM 0x00695b70
char g_industryActionCostWeightResCode08;
// GLOBAL: IMPERIALISM 0x00695b90
char g_industryActionCostWeightResCode10;
// GLOBAL: IMPERIALISM 0x00695bb0
char g_industryActionCostWeightResCode0B;
// GLOBAL: IMPERIALISM 0x00695bd0
char g_industryActionCostWeightResCode03;
// GLOBAL: IMPERIALISM 0x00695bf0
char g_industryActionCostWeightResCode0C;

static __inline short ReadWeight(const char* tableBase, short index) {
  return *reinterpret_cast<const short*>(tableBase + static_cast<unsigned int>(index) * 2);
}

static __inline void WriteShort(void* base, int offset, short value) {
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset) = value;
}

static __inline short ReadShort(void* base, int offset) {
  return *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset);
}

// FUNCTION: IMPERIALISM 0x004b8b80
void TCapacityOrder::FillOrderSheet(void* orderSheet) {
  const short quantity = static_cast<short>(reinterpret_cast<unsigned int>(orderSheet));
  short value = 0;

  this->Produce(orderSheet);

  value = static_cast<short>(ReadWeight(&g_industryActionCostWeightResCode09, this->resourceTypeIndex48) *
                             quantity);
  WriteShort(orderSheet, 0x12, value);
  if (value < 0) {
    WriteShort(orderSheet, 0x12, 0);
  }

  value = static_cast<short>(ReadWeight(&g_industryActionCostWeightResCode08, this->resourceTypeIndex48) *
                             quantity);
  WriteShort(orderSheet, 0x10, value);
  if (value < 0) {
    WriteShort(orderSheet, 0x10, 0);
  }

  value = static_cast<short>(ReadWeight(&g_industryActionCostWeightResCode10, this->resourceTypeIndex48) *
                             quantity);
  WriteShort(orderSheet, 0x20, value);
  if (ReadShort(orderSheet, 0x12) < 0) {
    WriteShort(orderSheet, 0x12, 0);
  }

  value = static_cast<short>(ReadWeight(&g_industryActionCostWeightResCode0B, this->resourceTypeIndex48) *
                             quantity);
  WriteShort(orderSheet, 0x16, value);
  if (value < 0) {
    WriteShort(orderSheet, 0x16, 0);
  }

  value = static_cast<short>(ReadWeight(&g_industryActionCostWeightResCode03, this->resourceTypeIndex48) *
                             quantity);
  WriteShort(orderSheet, 0x06, value);
  if (value < 0) {
    WriteShort(orderSheet, 0x06, 0);
  }

  value = static_cast<short>(ReadWeight(&g_industryActionCostWeightResCode0C, this->resourceTypeIndex48) *
                             quantity);
  WriteShort(orderSheet, 0x18, value);
  if (value < 0) {
    WriteShort(orderSheet, 0x18, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004b8cc0
CRuntimeClass* TCapacityOrder::GetRuntimeClass() {
  return &g_pClassDescTCapacityOrder;
}

// SYNTHETIC: IMPERIALISM 0x004b8d00
// TCapacityOrder::`scalar deleting destructor'
