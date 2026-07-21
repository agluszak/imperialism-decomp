#include "game/TInteriorMinister.h"

#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/global_data_tables.h"

// Slots 0x16-0x1f own bodies (honest stubs; slot ownership drives vtable matching).
// FUNCTION: IMPERIALISM 0x004be150
short TInteriorMinister::InteriorSlot1D(int arg) {
  return static_cast<short>(arg);
}

// FUNCTION: IMPERIALISM 0x004be170
short TInteriorMinister::InteriorSlot1E(int arg) {
  return static_cast<short>(arg);
}

// FUNCTION: IMPERIALISM 0x004be190
void TInteriorMinister::InteriorSlot1F(int) {}
// SYNTHETIC: IMPERIALISM 0x004be0d0
// TInteriorMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x004be1b0
// TInteriorMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInteriorMinister, TMinister)

// FUNCTION: IMPERIALISM 0x004be1d0
TInteriorMinister::TInteriorMinister() : TMinister() {}

// SYNTHETIC: IMPERIALISM 0x004be200
// TInteriorMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004be290
void TInteriorMinister::ReadFrom(TStream* stream) {
  TMinister::ReadFrom(stream);
  stream->ReadBytes(&field10, 2);
  stream->ReadBytes(&field12, 2);
  stream->ReadBytes(&capabilityFlag14, 2);
  stream->ReadBytes(&capabilityFlag16, 2);
  unsigned char* table = reinterpret_cast<unsigned char*>(trailingTable);
  stream->ReadBytes(table, sizeof(trailingTable));
  for (int i = 0; i < 7; ++i) {
    unsigned char lo = table[i * 2];
    table[i * 2] = table[i * 2 + 1];
    table[i * 2 + 1] = lo;
  }
}

// FUNCTION: IMPERIALISM 0x004be320
void TInteriorMinister::WriteTo(TStream* stream) {
  SerializeTMinisterBaseOrderArrayHeader(stream);
}

// FUNCTION: IMPERIALISM 0x004be3c0
short TInteriorMinister::DispatchNationStateEventCode10(short nationSlot) {
  (void)nationSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004be3f0
void TInteriorMinister::InteriorSlot1A(short) {}

// FUNCTION: IMPERIALISM 0x004be410
void TInteriorMinister::InteriorSlot1B(short) {}

// FUNCTION: IMPERIALISM 0x004be430
void TInteriorMinister::InteriorSlot1C(short) {}

// FUNCTION: IMPERIALISM 0x004be450
void TInteriorMinister::MinisterSlot12(short arg1, short arg2) {
  field12 = arg1;
  field10 = arg2;
}

// FUNCTION: IMPERIALISM 0x004be480
void TInteriorMinister::InteriorSlot16() {}

// FUNCTION: IMPERIALISM 0x004be4c0
void TInteriorMinister::InteriorSlot17() {}

// FUNCTION: IMPERIALISM 0x004be4f0
void TInteriorMinister::Call4C() {}

// Tops up up to 10 of the nation's needs (in the fixed priority order
// g_aInteriorMinisterNeedPriorityOrder_00696408) toward their current reading, stopping as
// soon as the nation's need-cap headroom (needCapA6 - needsOverCapFlag) hits zero. NOTE:
// TInteriorMinister::Call4C (0x4be4f0) and Call54 (0x4be5b0), plus
// TDefenseMinister::MinisterSlot14 (0x4b5dc0's sibling override at 0x4ec540, ~1.3KB with EH
// scaffolding), were discovered to be similarly wrongly stubbed as no-ops while
// investigating this slot; they are out of scope for this port and are left as a flagged
// follow-up rather than a silent no-op regression.
// FUNCTION: IMPERIALISM 0x004be520
void TInteriorMinister::MinisterSlot14() {
  short i = 0;
  do {
    short capRemaining =
        static_cast<short>(ownerContextAt04->needCapA6 - ownerContextAt04->needsOverCapFlag);
    if (capRemaining == 0) {
      break;
    }
    short needIndex = g_aInteriorMinisterNeedPriorityOrder_00696408[i];
    ++i;
    short current = ownerContextAt04->needCurrentByType[needIndex];
    short value = (current <= capRemaining) ? current : capRemaining;
    ownerContextAt04->UpdateNeedTargetAndAccumulateOverCap(needIndex, value);
  } while (i < 10);
}

// FUNCTION: IMPERIALISM 0x004be5b0
void TInteriorMinister::Call54() {}

// FUNCTION: IMPERIALISM 0x004be650
void TInteriorMinister::InteriorSlot18() {}

// FUNCTION: IMPERIALISM 0x004be690
void TInteriorMinister::InteriorSlot19() {}

// FUNCTION: IMPERIALISM 0x004be6d0
void TInteriorMinister::NoOpForeignMinisterUtilityStub(void* receiver) {
  (void)receiver;
}
