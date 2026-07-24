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

// FUNCTION: IMPERIALISM 0x004b21d0
void TLaborPool::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&lowSkillCount04, 2);
  stream->WriteBytesSlot78(&mediumSkillCount06, 2);
  stream->WriteBytesSlot78(&highSkillCount08, 2);
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
  short remaining = amount;
  short moved = lowSkillCount04 < remaining ? lowSkillCount04 : remaining;
  lowSkillCount04 = static_cast<short>(lowSkillCount04 - moved);
  destination->lowSkillCount04 = static_cast<short>(destination->lowSkillCount04 + moved);
  remaining = static_cast<short>(remaining - moved);

  moved = mediumSkillCount06 < remaining ? mediumSkillCount06 : remaining;
  mediumSkillCount06 = static_cast<short>(mediumSkillCount06 - moved);
  destination->mediumSkillCount06 = static_cast<short>(destination->mediumSkillCount06 + moved);
  remaining = static_cast<short>(remaining - moved);

  moved = highSkillCount08 < remaining ? highSkillCount08 : remaining;
  highSkillCount08 = static_cast<short>(highSkillCount08 - moved);
  destination->highSkillCount08 = static_cast<short>(destination->highSkillCount08 + moved);
  return remaining == 0;
}

// FUNCTION: IMPERIALISM 0x004b2340
short TLaborPool::TransferToHighSkillFirst(TLaborPool* destination, short amount) {
  short remaining = amount;
  short moved = highSkillCount08 < remaining ? highSkillCount08 : remaining;
  highSkillCount08 = static_cast<short>(highSkillCount08 - moved);
  destination->highSkillCount08 = static_cast<short>(destination->highSkillCount08 + moved);
  remaining = static_cast<short>(remaining - moved);

  moved = mediumSkillCount06 < remaining ? mediumSkillCount06 : remaining;
  mediumSkillCount06 = static_cast<short>(mediumSkillCount06 - moved);
  destination->mediumSkillCount06 = static_cast<short>(destination->mediumSkillCount06 + moved);
  remaining = static_cast<short>(remaining - moved);

  moved = lowSkillCount04 < remaining ? lowSkillCount04 : remaining;
  lowSkillCount04 = static_cast<short>(lowSkillCount04 - moved);
  destination->lowSkillCount04 = static_cast<short>(destination->lowSkillCount04 + moved);
  return remaining == 0;
}
