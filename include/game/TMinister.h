#pragma once

#include "decomp_types.h"

#include "game/mfc.h"
#include "game/TIndexAndRankList.h"

class TStream;

#include "game/TObject.h"

// Minister base — fork-class construction (ConstructTMinister writes skillIndexC + vptr only).
// VTABLE: IMPERIALISM 0x00659c00
class TMinister : public TObject {
public:
  TMinister();
  void InitializeBaseOrderArray(undefined4 ownerContext);
  virtual ~TMinister(); // slot 1 — body @ 0x0052ebd0 (DestructTMinister)

  DECLARE_DYNCREATE(TMinister)
  // slot 1 — scalar deleting destructor @ 0x0052eba0 (SYNTHETIC)
  void WriteTo(TStream* stream) override;  // 5 (0x14)
  void ReadFrom(TStream* stream) override; // 6 (0x18)
  void
  SerializeTMinisterBaseOrderArrayHeader(TStream* stream); // Ghidra alias for WriteTo @ 0x52ecf0
  void Free() override;                                    // 7 (0x1c)
  virtual short DispatchNationStateEventCode10(short nationSlot);  // 10 (0x28)
  virtual void RebuildTerrainPreferenceEntriesAndAssignRanks();    // 11 (0x2c)
  virtual short MapTerrainTypeToPreferenceRank(short terrainType); // 12 (0x30)
  virtual short MapPreferenceRankToTerrainType(short rank);        // 13 (0x34)
  virtual short GetPreferenceTerrainTypeByEntryIndex(short index); // 14 (0x38)
  virtual short GetPreferenceGroupRankByEntryIndex(short index);   // 15 (0x3c)
  virtual short GetPreferenceScoreByEntryIndex(short index);       // 16 (0x40)
  virtual void NoOpForeignMinisterUtilityStub(void* receiver);     // 17 (0x44)
  // Orig TMinister vtable (0x659c00) ends at slot 17 (0x44); slots 0x48-0x54 are NULL.
  // Slots 0x48+ are introduced per derived minister (e.g. TDefenseMinister, TInteriorMinister).

  int ownerContextAt04;       // +0x4 — great-power back-pointer from InitializeBaseOrderArray
  TIndexAndRankList* field_8; // +0x8 — minister order array (vtable 0x659c58)
  short skillIndexC;          // +0xC
  unsigned char pad0e[0x14 - 0x0E];
  // +0x14/+0x16 — every TCityInteriorMinister-family constructor (TSteelCityMinister,
  // TShipBuilderCityMinister, TEvenCityMinister, ...) sets both to 1; no differentiating
  // value observed across ministers, semantic beyond "capability flag pair" unconfirmed.
  short capabilityFlag14;
  short capabilityFlag16;
  unsigned char pad18[0x24 - 0x18];
  short capabilityFlag24;
  short capabilityFlag26;
  short capabilityFlag28;
};
