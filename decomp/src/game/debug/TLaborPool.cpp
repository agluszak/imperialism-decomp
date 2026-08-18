#include "game/debug/TLaborPool.h"

#include "game/core/TStream.h"
// SYNTHETIC: IMPERIALISM 0x004b20d0
// TLaborPool::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b2110
// TLaborPool::GetRuntimeClass

IMPLEMENT_DYNCREATE(TLaborPool, TObject)
// SYNTHETIC: IMPERIALISM 0x004b2160
// TLaborPool::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b2190
TLaborPool::~TLaborPool() {}

// FUNCTION: IMPERIALISM 0x004b21b0
void TLaborPool::ILaborPool() {
  mediumSkillCount06 = 0;
  lowSkillCount04 = 0;
  highSkillCount08 = 0;
}

// FUNCTION: IMPERIALISM 0x004b21d0
void TLaborPool::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&lowSkillCount04, 2);
  stream->WriteBytes(&mediumSkillCount06, 2);
  stream->WriteBytes(&highSkillCount08, 2);
}

// FUNCTION: IMPERIALISM 0x004b2220
void TLaborPool::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&lowSkillCount04, 2);
  stream->ReadBytes(&mediumSkillCount06, 2);
  stream->ReadBytes(&highSkillCount08, 2);
}

// FUNCTION: IMPERIALISM 0x004b2270
short TLaborPool::TransferToLowSkillFirst(TLaborPool* destination, short amount) {
  if (lowSkillCount04 >= amount) {
    lowSkillCount04 = static_cast<short>(lowSkillCount04 - amount);
    destination->lowSkillCount04 = static_cast<short>(destination->lowSkillCount04 + amount);
    return 1;
  }

  destination->lowSkillCount04 = static_cast<short>(destination->lowSkillCount04 + lowSkillCount04);
  amount = static_cast<short>(amount - lowSkillCount04);
  lowSkillCount04 = 0;
  if (mediumSkillCount06 >= amount) {
    mediumSkillCount06 = static_cast<short>(mediumSkillCount06 - amount);
    destination->mediumSkillCount06 = static_cast<short>(destination->mediumSkillCount06 + amount);
    return 1;
  }

  destination->mediumSkillCount06 =
      static_cast<short>(destination->mediumSkillCount06 + mediumSkillCount06);
  amount = static_cast<short>(amount - mediumSkillCount06);
  mediumSkillCount06 = 0;
  if (highSkillCount08 >= amount) {
    highSkillCount08 = static_cast<short>(highSkillCount08 - amount);
    destination->highSkillCount08 = static_cast<short>(destination->highSkillCount08 + amount);
    return 1;
  }

  destination->highSkillCount08 = highSkillCount08;
  highSkillCount08 = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b2340
short TLaborPool::TransferToHighSkillFirst(TLaborPool* destination, short amount) {
  if (highSkillCount08 >= amount) {
    highSkillCount08 = static_cast<short>(highSkillCount08 - amount);
    destination->highSkillCount08 = static_cast<short>(destination->highSkillCount08 + amount);
    return 1;
  }

  destination->highSkillCount08 =
      static_cast<short>(destination->highSkillCount08 + highSkillCount08);
  amount = static_cast<short>(amount - highSkillCount08);
  highSkillCount08 = 0;
  if (mediumSkillCount06 >= amount) {
    mediumSkillCount06 = static_cast<short>(mediumSkillCount06 - amount);
    destination->mediumSkillCount06 = static_cast<short>(destination->mediumSkillCount06 + amount);
    return 1;
  }

  destination->mediumSkillCount06 =
      static_cast<short>(destination->mediumSkillCount06 + mediumSkillCount06);
  amount = static_cast<short>(amount - mediumSkillCount06);
  mediumSkillCount06 = 0;
  if (lowSkillCount04 >= amount) {
    lowSkillCount04 = static_cast<short>(lowSkillCount04 - amount);
    destination->lowSkillCount04 = static_cast<short>(destination->lowSkillCount04 + amount);
    return 1;
  }

  destination->lowSkillCount04 = lowSkillCount04;
  lowSkillCount04 = 0;
  return 0;
}
