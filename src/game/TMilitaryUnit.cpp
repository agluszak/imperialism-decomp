#include "game/TMilitaryUnit.h"

#include "game/TAdmiral.h"
#include "game/TStream.h"
#include "game/global_data_tables.h"

extern "C" char g_pClassDescTMilitaryUnit = 0;

// SYNTHETIC: IMPERIALISM 0x005c2cb0
// TMilitaryUnit::CreateObject

// SYNTHETIC: IMPERIALISM 0x005c2dd0
// TMilitaryUnit::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMilitaryUnit, TUnit)

// FUNCTION: IMPERIALISM 0x005c2df0
TMilitaryUnit::TMilitaryUnit()
    : name24(), field_38(0), field_3A(0), field_3C(0), ownerMission40(nullptr) {
  field_1C = 1;
  field_34 = 0x1f4;
  field_36 = 0;
  CString empty(g_szEmptyString); // temp -> 0x00605950, ~ -> 0x006058e2
  name24 = empty;                 // -> 0x00605a29 CString::operator=
}

// SYNTHETIC: IMPERIALISM 0x005c2ed0
// TMilitaryUnit::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005c2f00
TMilitaryUnit::~TMilitaryUnit() {}

// FUNCTION: IMPERIALISM 0x005c2f50
void TMilitaryUnit::InitializeRecruitOrderState(short capValue, int nodeContext, short nationSlot) {
  field_1C = 1;
  field_6 = static_cast<short>(-1);
  RegisterUnitOrderWithOwnerManager(capValue, nodeContext, nationSlot, 0);
  field_36 = static_cast<short>(
      (static_cast<int>(capValue) + (static_cast<int>(capValue) >> 31 & 7)) >> 3);
  if (capValue > 0x1b) {
    TAdmiral::GenerateMappedFlavorTextByNationSlotField0C(
        static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[nationSlot]), &name24);
  }
  CopyUnitCurrentTileIntoOrderTargets();
}

static void SwapAdjacentBytesInShortArray(short* entries, int pairCount) {
  for (int i = 0; i < pairCount; ++i) {
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&entries[i]);
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
  }
}

// FUNCTION: IMPERIALISM 0x005c2fd0
void TMilitaryUnit::ReadFrom(TStream* stream) {
  TUnit::ReadFrom(stream);
  // name24 (CString) is read here in the original via TStream slot 0x70
  // (streamSlot70, confirmed 2-arg "read shared string with capacity" --
  // args &name24, 0x20 -- same slot TCountry::ReadFrom 0x4d6bf0 calls with
  // &identitySharedString0/1, 0xff). Left as the 0-arg placeholder: widening
  // the shared TStream vtable slot's signature touches TStream::streamSlot70
  // (0x488c50), TFileStream::streamSlot70 (0x489360), and TCountry's two call
  // sites, which is out of this class's scope -- see bd 1uj.6.
  stream->streamSlot70();
  stream->ReadBytes(orderTargetTiles28, 6);
  SwapAdjacentBytesInShortArray(orderTargetTiles28, 3);
  stream->ReadBytes(orderTargetTilesMirror2E, 6);
  SwapAdjacentBytesInShortArray(orderTargetTilesMirror2E, 3);
  stream->ReadBytes(&field_34, 2);
  stream->ReadBytes(&field_36, 2);
  stream->ReadBytes(&field_38, 2);
  stream->ReadBytes(&field_3A, 2);
}

// FUNCTION: IMPERIALISM 0x005c30a0
void TMilitaryUnit::WriteTo(TStream* stream) {
  TUnit::WriteTo(stream);
  stream->streamSlotAc(&name24);
  for (int i = 0; i < 3; ++i) {
    short swapped = orderTargetTiles28[i];
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&swapped);
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
    stream->WriteBytesSlot78(&swapped, 2);
  }
  for (int j = 0; j < 3; ++j) {
    short swapped = orderTargetTilesMirror2E[j];
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&swapped);
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
    stream->WriteBytesSlot78(&swapped, 2);
  }
  stream->WriteBytesSlot78(&field_34, 2);
  stream->WriteBytesSlot78(&field_36, 2);
  stream->WriteBytesSlot78(&field_38, 2);
  stream->WriteBytesSlot78(&field_3A, 2);
}

// FUNCTION: IMPERIALISM 0x005c3190
void TMilitaryUnit::CopyUnitCurrentTileIntoOrderTargets() {
  short tile = field_6;
  short* cursor = orderTargetTilesMirror2E;
  int remaining = 3;
  do {
    cursor[-3] = tile; // lands in orderTargetTiles28[]
    *cursor = tile;
    ++cursor;
    --remaining;
  } while (remaining != 0);
}

// FUNCTION: IMPERIALISM 0x005c31c0
void TMilitaryUnit::DetachUnitOrderFromOwnerAndReset() {}

// FUNCTION: IMPERIALISM 0x005c3200
void TMilitaryUnit::VTableSlot10(int pOwnerContext) {
  (void)pOwnerContext;
}

// FUNCTION: IMPERIALISM 0x005c3400
short TMilitaryUnit::GetUnitTypeCostPoints() {
  short unitType = orderType;
  if (unitType == 0x1b || unitType == 0x1c || unitType == 0x1d) {
    return 1;
  }
  if (g_UnitTypeMilitaryStatTable_00695CD2[unitType][0] == 0x10) {
    return g_UnitTypeMilitaryStatTable_00695CD2[unitType][1];
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005c3490
short TMilitaryUnit::GetUnitMovementClassId() {
  return g_awTacticalUnitCategoryCodeBySlot[this->orderType];
}

// FUNCTION: IMPERIALISM 0x005c34d0
short TMilitaryUnit::IsNotStationedInProvince(short provinceId) {
  return field_6 != provinceId;
}

// FUNCTION: IMPERIALISM 0x005c3530
short TMilitaryUnit::GetUnitTypeStatPercent(short statIndex) {
  return static_cast<short>((g_UnitTypeStatTable_0066EB88[orderType][statIndex] * 100) /
                            g_UnitTypeStatDivisorTable_0066ED30[statIndex]);
}
