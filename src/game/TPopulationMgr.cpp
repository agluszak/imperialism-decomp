#include "game/TPopulationMgr.h"

#include <string.h>

#include "game/TCity.h"
#include "game/TStream.h"
// SYNTHETIC: IMPERIALISM 0x004b5b40
// TPopulationMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b5b70
// TPopulationMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPopulationMgr, TObject)

TPopulationMgr::TPopulationMgr() {}

// SYNTHETIC: IMPERIALISM 0x004b5bb0
// TPopulationMgr::`scalar deleting destructor'
TPopulationMgr::~TPopulationMgr() {}

// FUNCTION: IMPERIALISM 0x004b5c00
void TPopulationMgr::InitializePopulationState(TCity* city) {
  city04 = city;
  baselineSlots10 = new TLaborPool();
  productionSlots14 = new TLaborPool();
  pendingDeltaSlots18 = new TLaborPool();
  populationCount08 = 0;
  populationCountFloat0c = 0.0f;
  extraAt1e = 0;
  memset(serializedState22, 0, sizeof(serializedState22));
}

// FUNCTION: IMPERIALISM 0x004b5d10
undefined TPopulationMgr::OrphanLeaf_NoCall_Ins09_004b5d10(int param_1, int param_2) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b5d50
undefined TPopulationMgr::OrphanLeaf_NoCall_Ins20_004b5d50(short param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b5dc0
void TPopulationMgr::SetPopulation(short lowSkillCount, short mediumSkillCount,
                                   short highSkillCount) {
  baselineSlots10->lowSkillCount04 = lowSkillCount;
  productionSlots14->lowSkillCount04 = lowSkillCount;
  baselineSlots10->mediumSkillCount06 = mediumSkillCount;
  productionSlots14->mediumSkillCount06 = mediumSkillCount;
  baselineSlots10->highSkillCount08 = highSkillCount;
  productionSlots14->highSkillCount08 = highSkillCount;

  stockLevel1c = static_cast<short>(
      productionSlots14->lowSkillCount04 +
      (productionSlots14->mediumSkillCount06 + productionSlots14->highSkillCount08 * 2) * 2);
  short total = static_cast<short>(mediumSkillCount + highSkillCount + lowSkillCount);
  populationCount08 = total;
  populationCountFloat0c = static_cast<float>(total);

  pendingDeltaSlots18->highSkillCount08 = 0;
  pendingDeltaSlots18->mediumSkillCount06 = 0;
  pendingDeltaSlots18->lowSkillCount04 = 0;
  fieldAt20 = 0;
}

// FUNCTION: IMPERIALISM 0x004b5e80
undefined TPopulationMgr::OrphanCallChain_C2_I24_004b5e80() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b5ed0
undefined TPopulationMgr::PopulationMgrSlot0E() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b6260
undefined TPopulationMgr::GetRecentStormImpactMetrics(short* damageOut, ushort* eventCountOut) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b63e0
undefined TPopulationMgr::OrphanLeaf_NoCall_Ins50_004b63e0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b64c0
undefined TPopulationMgr::OrphanLeaf_NoCall_Ins63_004b64c0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b65b0
undefined TPopulationMgr::OrphanCallChain_C2_I61_004b65b0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b66a0
void TPopulationMgr::RemovePopulation(short startingSkillBand, short amount) {
  short remaining = amount;

  if (startingSkillBand == 1) {
    short available = baselineSlots10->lowSkillCount04;
    if (available < remaining) {
      remaining = static_cast<short>(remaining - available);
      baselineSlots10->lowSkillCount04 = 0;
      productionSlots14->lowSkillCount04 = 0;
      startingSkillBand = 2;
      stockLevel1c = static_cast<short>(stockLevel1c - remaining);
    } else {
      baselineSlots10->lowSkillCount04 = static_cast<short>(available - remaining);
      productionSlots14->lowSkillCount04 =
          static_cast<short>(productionSlots14->lowSkillCount04 - remaining);
      stockLevel1c = static_cast<short>(stockLevel1c - remaining);
      remaining = 0;
    }
  }

  if (startingSkillBand == 2) {
    short available = baselineSlots10->mediumSkillCount06;
    if (available < remaining) {
      remaining = static_cast<short>(remaining - available);
      baselineSlots10->mediumSkillCount06 = 0;
      productionSlots14->mediumSkillCount06 = 0;
      startingSkillBand = 4;
      stockLevel1c = static_cast<short>(stockLevel1c - remaining * 2);
    } else {
      baselineSlots10->mediumSkillCount06 = static_cast<short>(available - remaining);
      productionSlots14->mediumSkillCount06 =
          static_cast<short>(productionSlots14->mediumSkillCount06 - remaining);
      stockLevel1c = static_cast<short>(stockLevel1c - remaining * 2);
      remaining = 0;
    }
  }

  if (startingSkillBand == 4) {
    short available = baselineSlots10->highSkillCount08;
    if (available < remaining) {
      remaining = static_cast<short>(remaining - available);
      baselineSlots10->highSkillCount08 = 0;
      productionSlots14->highSkillCount08 = 0;
      stockLevel1c = static_cast<short>(stockLevel1c - remaining * 4);
    } else {
      baselineSlots10->highSkillCount08 = static_cast<short>(available - remaining);
      productionSlots14->highSkillCount08 =
          static_cast<short>(productionSlots14->highSkillCount08 - remaining);
      stockLevel1c = static_cast<short>(stockLevel1c - remaining * 4);
      remaining = 0;
    }
  }

  short removed = static_cast<short>(amount - remaining);
  populationCount08 = static_cast<short>(populationCount08 - removed);
  populationCountFloat0c -= static_cast<float>(removed);
}

// FUNCTION: IMPERIALISM 0x004b67e0
undefined TPopulationMgr::OrphanLeaf_NoCall_Ins26_004b67e0(short param_1, short param_2) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b6850
void TPopulationMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&populationCount08, 2);
  stream->WriteBytesSlot78(&stockLevel1c, 2);
  stream->WriteBytesSlot78(&extraAt1e, 2);
  stream->WriteBytesSlot78(&fieldAt20, 2);
  stream->WriteBytesSlot78(serializedState22, sizeof(serializedState22));
  stream->WriteBytesSlot78(&populationCountFloat0c, 4);
  baselineSlots10->WriteTo(stream);
  productionSlots14->WriteTo(stream);
  pendingDeltaSlots18->WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x004b68f0
void TPopulationMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&populationCount08, 2);
  stream->ReadBytes(&stockLevel1c, 2);
  stream->ReadBytes(&extraAt1e, 2);
  stream->ReadBytes(&fieldAt20, 2);
  stream->ReadBytes(serializedState22, sizeof(serializedState22));
  stream->ReadBytes(&populationCountFloat0c, 4);
  baselineSlots10->ReadFrom(stream);
  productionSlots14->ReadFrom(stream);
  pendingDeltaSlots18->ReadFrom(stream);
}

// FUNCTION: IMPERIALISM 0x004b6990
void TPopulationMgr::Free() {
  if (baselineSlots10 != 0) {
    baselineSlots10->Free();
  }
  baselineSlots10 = 0;
  if (productionSlots14 != 0) {
    productionSlots14->Free();
  }
  productionSlots14 = 0;
  if (pendingDeltaSlots18 != 0) {
    pendingDeltaSlots18->Free();
  }
  pendingDeltaSlots18 = 0;
  delete this;
}

short* TPopulationMgr::GetSummaryArraySlot50() {
  return reinterpret_cast<short*>(OrphanLeaf_NoCall_Ins63_004b64c0());
}
