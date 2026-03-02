// TCapacityOrder class wrappers promoted from ghidra_autogen.

#include "decomp_types.h"

void FreeHeapBufferIfNotNull(undefined4 ptrValue);

// GLOBAL: IMPERIALISM 0x64f440
char g_pClassDescTCapacityOrder;
// GLOBAL: IMPERIALISM 0x66fec4
char PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;
// GLOBAL: IMPERIALISM 0x695b50
char g_industryActionCostWeightResCode09;
// GLOBAL: IMPERIALISM 0x695b70
char g_industryActionCostWeightResCode08;
// GLOBAL: IMPERIALISM 0x695b90
char g_industryActionCostWeightResCode10;
// GLOBAL: IMPERIALISM 0x695bb0
char g_industryActionCostWeightResCode0B;
// GLOBAL: IMPERIALISM 0x695bd0
char g_industryActionCostWeightResCode03;
// GLOBAL: IMPERIALISM 0x695bf0
char g_industryActionCostWeightResCode0C;

class TCapacityOrder {
public:
  void* pVtable;
  unsigned char pad_04[0x44];
  unsigned char field69_0x48;

  void thunk_DestructTCapacityOrderAndMaybeFree(void);
  void thunk_CreateTCapacityOrderInstance(void* pTargetOrder);
  static void* __cdecl thunk_GetTCapacityOrderClassNamePointer(void);
  void CreateTCapacityOrderInstance(void* pTargetOrder);
  static void* __cdecl GetTCapacityOrderClassNamePointer(void);
  TCapacityOrder* ConstructTCapacityOrderBaseState(unsigned char freeSelfFlag);
  void DestructTCapacityOrderAndMaybeFree(void);
};

static __inline short ReadWeight(const char* tableBase, unsigned char index) {
  return *reinterpret_cast<const short*>(tableBase + static_cast<unsigned int>(index) * 2);
}

static __inline void WriteShort(void* base, int offset, short value) {
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset) = value;
}

static __inline short ReadShort(void* base, int offset) {
  return *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset);
}

// FUNCTION: IMPERIALISM 0x00401c0d
void TCapacityOrder::thunk_DestructTCapacityOrderAndMaybeFree(void) {
  this->DestructTCapacityOrderAndMaybeFree();
}

// FUNCTION: IMPERIALISM 0x00404093
void TCapacityOrder::thunk_CreateTCapacityOrderInstance(void* pTargetOrder) {
  this->CreateTCapacityOrderInstance(pTargetOrder);
}

// FUNCTION: IMPERIALISM 0x00405ab5
void* __cdecl TCapacityOrder::thunk_GetTCapacityOrderClassNamePointer(void) {
  return GetTCapacityOrderClassNamePointer();
}

// FUNCTION: IMPERIALISM 0x004b8b80
void TCapacityOrder::CreateTCapacityOrderInstance(void* pTargetOrder) {
  typedef void(__fastcall* Slot3CFn)(TCapacityOrder* self, int unusedEdx, void* arg);
  const short quantity = static_cast<short>(reinterpret_cast<unsigned int>(pTargetOrder));
  short value = 0;

  (reinterpret_cast<Slot3CFn>(reinterpret_cast<int*>(this->pVtable)[0x0f]))(this, 0, pTargetOrder);

  value =
      static_cast<short>(ReadWeight(&g_industryActionCostWeightResCode09, this->field69_0x48) *
                         quantity);
  WriteShort(pTargetOrder, 0x12, value);
  if (value < 0) {
    WriteShort(pTargetOrder, 0x12, 0);
  }

  value =
      static_cast<short>(ReadWeight(&g_industryActionCostWeightResCode08, this->field69_0x48) *
                         quantity);
  WriteShort(pTargetOrder, 0x10, value);
  if (value < 0) {
    WriteShort(pTargetOrder, 0x10, 0);
  }

  value =
      static_cast<short>(ReadWeight(&g_industryActionCostWeightResCode10, this->field69_0x48) *
                         quantity);
  WriteShort(pTargetOrder, 0x20, value);
  if (ReadShort(pTargetOrder, 0x12) < 0) {
    WriteShort(pTargetOrder, 0x12, 0);
  }

  value =
      static_cast<short>(ReadWeight(&g_industryActionCostWeightResCode0B, this->field69_0x48) *
                         quantity);
  WriteShort(pTargetOrder, 0x16, value);
  if (value < 0) {
    WriteShort(pTargetOrder, 0x16, 0);
  }

  value =
      static_cast<short>(ReadWeight(&g_industryActionCostWeightResCode03, this->field69_0x48) *
                         quantity);
  WriteShort(pTargetOrder, 0x18, value);
  if (value < 0) {
    WriteShort(pTargetOrder, 0x18, 0);
  }

  value =
      static_cast<short>(ReadWeight(&g_industryActionCostWeightResCode0C, this->field69_0x48) *
                         quantity);
  WriteShort(pTargetOrder, 0x18, value);
  if (value < 0) {
    WriteShort(pTargetOrder, 0x18, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004b8cc0
void* __cdecl TCapacityOrder::GetTCapacityOrderClassNamePointer(void) {
  return &g_pClassDescTCapacityOrder;
}

// FUNCTION: IMPERIALISM 0x004b8d00
TCapacityOrder* TCapacityOrder::ConstructTCapacityOrderBaseState(unsigned char freeSelfFlag) {
  this->thunk_DestructTCapacityOrderAndMaybeFree();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(this)));
  }
  return this;
}

// FUNCTION: IMPERIALISM 0x004b8d30
void TCapacityOrder::DestructTCapacityOrderAndMaybeFree(void) {
  this->pVtable = &PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;
}
