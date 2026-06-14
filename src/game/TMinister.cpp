#include "game/TMinister.h"

#include "game/CRuntimeClass.h"
#include "game/TMinisterBaseOrderArray.h"
#include "game/TStream.h"

#include <new>

void __stdcall NoOpForeignMinisterUtilityStub(int);

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
CRuntimeClass g_pClassDescTMinister = {0};
}

extern char PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);

// FUNCTION: IMPERIALISM 0x0052eb60
CRuntimeClass* TMinister::GetRuntimeClass() {
  return &g_pClassDescTMinister;
}

// FUNCTION: IMPERIALISM 0x0052eb80
#pragma optimize("y", on)
TMinister::TMinister() : ownerContextAt04(0), field_8(0), skillIndexC(0) {}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x0052ebf0
void TMinister::InitializeBaseOrderArray(undefined4 ownerContext) {
  this->ownerContextAt04 = ownerContext;
  void* storage = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x18));
  if (storage == 0) {
    this->field_8 = 0;
    return;
  }
  this->field_8 = new (storage) TMinisterBaseOrderArray();
}

// FUNCTION: IMPERIALISM 0x0052ebd0
#pragma optimize("y", on)
void DestructTMinister(TMinister* minister) {
  *reinterpret_cast<void**>(minister) = &PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x0052eba0
TMinister* __fastcall DestructTMinisterAndMaybeFree(TMinister* minister, int unusedEdx,
                                                    unsigned char freeSelfFlag) {
  (void)unusedEdx;
  DestructTMinister(minister);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)minister);
  }
  return minister;
}

// FUNCTION: IMPERIALISM 0x0052ecf0
void TMinister::SerializeTMinisterBaseOrderArrayHeader(TStream* archive) {
  TMinister::Serialize(reinterpret_cast<CArchive*>(archive));
  archive->WriteBytesSlot78(&this->skillIndexC, 2);
}

// FUNCTION: IMPERIALISM 0x0052ecc0
void TMinister::Call18(int arg1) {
  TStream* archive = reinterpret_cast<TStream*>(arg1);
  TMinister::Serialize(reinterpret_cast<CArchive*>(archive));
  archive->ReadBytes(&this->skillIndexC, 2);
}

// FUNCTION: IMPERIALISM 0x0052ec80
void __fastcall DeleteForeignMinisterAndReleaseOrderArray(TMinister* minister) {
  TIndexAndRankList* orderArray = minister->field_8;
  if (orderArray != 0) {
    orderArray->ReleaseSlot24();
  }
  minister->field_8 = 0;
  if (minister != 0) {
    delete minister;
  }
}

void TMinister::Call1C() { DeleteForeignMinisterAndReleaseOrderArray(this); }

void TMinister::Serialize(CArchive* ar) { (void)ar; }
void TMinister::AssertValidOrSlot0c() {}
void TMinister::DumpOrSlot10(int unused) { (void)unused; }
void TMinister::InvokeObjectSlot20() {}
void TMinister::CopyPayloadSlot24() {}
void TMinister::MinisterSlot0A() {}
void TMinister::MinisterSlot0B() {}
void TMinister::MinisterSlot0C() {}
void TMinister::MinisterSlot0D() {}
void TMinister::MinisterSlot0E() {}
void TMinister::MinisterSlot0F() {}
void TMinister::MinisterSlot10() {}
void TMinister::NotifySlot44(void* receiver) {
  NoOpForeignMinisterUtilityStub(reinterpret_cast<int>(receiver));
}
void TMinister::MinisterSlot12() {}
void TMinister::Call4C() {}
void TMinister::MinisterSlot14() {}
void TMinister::Call54() {}
void TMinister::Call58() {}
void TMinister::MinisterSlot17() {}
void TMinister::MinisterSlot18() {}
void TMinister::MinisterSlot19() {}
void TMinister::MinisterSlot1A(short arg) { (void)arg; }
void TMinister::MinisterSlot1B() {}
void TMinister::MinisterSlot1C() {}
void TMinister::MinisterSlot1D() {}
void TMinister::MinisterSlot1E() {}
void TMinister::MinisterSlot1F() {}
void TMinister::Call80() {}
void TMinister::MinisterSlot21() {}
char TMinister::MinisterSlot22() { return 0; }
void TMinister::Call8C() {}
void TMinister::Call90() {}
void TMinister::Call94() {}
void TMinister::DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
}
void TMinister::RecomputeOrderStateSlot9C() {}
void TMinister::MinisterSlot28() {}
void TMinister::MinisterSlot29() {}
void TMinister::MinisterSlot2A() {}
void TMinister::MinisterSlot2B() {}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
