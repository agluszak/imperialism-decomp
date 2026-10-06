#include "game/debug/TLaborPool.h"

#include "game/core/TStream.h"

IMPLEMENT_DYNCREATE(TLaborPool, TObject)
// FUNCTION: IMPERIALISM 0x004b2190
TLaborPool::~TLaborPool() {}

// FUNCTION: IMPERIALISM 0x004b21b0
void TLaborPool::ILaborPool() {
  mediumSkillCount = 0;
  lowSkillCount = 0;
  highSkillCount = 0;
}

// FUNCTION: IMPERIALISM 0x004b21d0
void TLaborPool::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&lowSkillCount, 2);
  stream->WriteBytes(&mediumSkillCount, 2);
  stream->WriteBytes(&highSkillCount, 2);
}

// FUNCTION: IMPERIALISM 0x004b2220
void TLaborPool::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&lowSkillCount, 2);
  stream->ReadBytes(&mediumSkillCount, 2);
  stream->ReadBytes(&highSkillCount, 2);
}

// FUNCTION: IMPERIALISM 0x004b2270
short TLaborPool::TransferToLowSkillFirst(TLaborPool* destination, short amount) {
  if (lowSkillCount >= amount) {
    lowSkillCount = static_cast<short>(lowSkillCount - amount);
    destination->lowSkillCount = static_cast<short>(destination->lowSkillCount + amount);
    return 1;
  }

  destination->lowSkillCount = static_cast<short>(destination->lowSkillCount + lowSkillCount);
  amount = static_cast<short>(amount - lowSkillCount);
  lowSkillCount = 0;
  if (mediumSkillCount >= amount) {
    mediumSkillCount = static_cast<short>(mediumSkillCount - amount);
    destination->mediumSkillCount = static_cast<short>(destination->mediumSkillCount + amount);
    return 1;
  }

  destination->mediumSkillCount =
      static_cast<short>(destination->mediumSkillCount + mediumSkillCount);
  amount = static_cast<short>(amount - mediumSkillCount);
  mediumSkillCount = 0;
  if (highSkillCount >= amount) {
    highSkillCount = static_cast<short>(highSkillCount - amount);
    destination->highSkillCount = static_cast<short>(destination->highSkillCount + amount);
    return 1;
  }

  destination->highSkillCount = highSkillCount;
  highSkillCount = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b2340
short TLaborPool::TransferToHighSkillFirst(TLaborPool* destination, short amount) {
  if (highSkillCount >= amount) {
    highSkillCount = static_cast<short>(highSkillCount - amount);
    destination->highSkillCount = static_cast<short>(destination->highSkillCount + amount);
    return 1;
  }

  destination->highSkillCount = static_cast<short>(destination->highSkillCount + highSkillCount);
  amount = static_cast<short>(amount - highSkillCount);
  highSkillCount = 0;
  if (mediumSkillCount >= amount) {
    mediumSkillCount = static_cast<short>(mediumSkillCount - amount);
    destination->mediumSkillCount = static_cast<short>(destination->mediumSkillCount + amount);
    return 1;
  }

  destination->mediumSkillCount =
      static_cast<short>(destination->mediumSkillCount + mediumSkillCount);
  amount = static_cast<short>(amount - mediumSkillCount);
  mediumSkillCount = 0;
  if (lowSkillCount >= amount) {
    lowSkillCount = static_cast<short>(lowSkillCount - amount);
    destination->lowSkillCount = static_cast<short>(destination->lowSkillCount + amount);
    return 1;
  }

  destination->lowSkillCount = lowSkillCount;
  lowSkillCount = 0;
  return 0;
}
