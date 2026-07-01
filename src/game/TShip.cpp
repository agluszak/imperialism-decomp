#include "game/TShip.h"

#include "game/TAdmiral.h"
#include "game/TGreatPower.h"
#include "game/TZone.h"
#include "game/TStream.h"
#include "game/GameAssert.h"
#include "game/global_data_tables.h"
#include "game/map_action_context_helpers.h"
#include "game/ui_invalidation_guard.h"
#include "game/CString.h"

#include <new>

extern "C" TShip* g_pNavyPrimaryOrderListHead = 0;
extern short g_industryActionCostWeightResCode10[16];
char g_ResourceDescriptorWeightWord0Base0069811c[0x24 * 64] = {0};

extern "C" {
extern short g_Resolve_Map_Order_LookupTable_00698108[];
extern short g_Calculate_Mission_Order_LookupTable_0069810C[];
extern short g_Navy_Order_Priority_LookupTable_00698118[];
extern short g_Task_Force_Order_LookupTable_00698110[];
}

extern undefined4 FindMapActionContextByNodeId(void);

static short SignedMod100(short value) {
  return (short)((value / 100 + (value >> 15)) -
                 (short)(((__int64)(int)value * 0x51eb851f) >> 0x3f));
}

static short SignedDiv10(int value) {
  return (short)(((short)(value / 10) + (short)(value >> 0x1f)) -
                 (short)(((__int64)value * 0x66666667) >> 0x3f));
}

static int* NavyZoneOrderDescriptorEnabledFlagPtr(short zoneIndex);
static short* NavyZoneOrderDescriptorStockCapPtr(short zoneIndex);

// FUNCTION: IMPERIALISM 0x004e0460
int SumNavyOrderPriorityForNationAndNodeType(TGreatPower* nationObj, int nodeType) {
  int sum = 0;
  for (TShip* node = static_cast<TShip*>(GetNavyPrimaryOrderListHead()); node != 0;
       node = node->nextOlder24) {
    if (node->ownerNationSlot14 == nationObj->nationSlot && node->field08 == (void*)nodeType) {
      sum += ComputeOrderNodeCompositeEconomicScore(node);
    }
  }
  return sum;
}

// FUNCTION: IMPERIALISM 0x004e04b0
int SumNavyOrderPriorityForNation(TGreatPower* nationObj) {
  int sum = 0;
  for (TShip* node = static_cast<TShip*>(GetNavyPrimaryOrderListHead()); node != 0;
       node = node->nextOlder24) {
    if (node->ownerNationSlot14 == nationObj->nationSlot) {
      sum += ComputeOrderNodeCompositeEconomicScore(node);
    }
  }
  return sum;
}
// SYNTHETIC: IMPERIALISM 0x0054f460
// TShip::CreateObject

IMPLEMENT_DYNCREATE(TShip, TObject)

// FUNCTION: IMPERIALISM 0x0054f500
TShip::TShip()
    : TObject(), displayName18(), resourceType04(0), pad06(0), field08(0), linkContext0c(0),
      linkTag0e(0), quantityFlag10(1), ownerNationSlot14(static_cast<short>(-1)),
      stockLevel1c(0), pad1e(0), field20(0), nextOlder24(g_pNavyPrimaryOrderListHead),
      prevNewer28(0), field2c(0), field30(0), field34(0) {
  g_pNavyPrimaryOrderListHead = this;
  if (nextOlder24 != 0) {
    nextOlder24->prevNewer28 = this;
  }
}

// SYNTHETIC: IMPERIALISM 0x0054f5c0
// TShip::`scalar deleting destructor'
TShip::~TShip() {}

// FUNCTION: IMPERIALISM 0x0054f640
void TShip::Free() {
  if (g_pNavyPrimaryOrderListHead == this) {
    g_pNavyPrimaryOrderListHead = this->nextOlder24;
  }
  if (this->nextOlder24 != 0) {
    this->nextOlder24->prevNewer28 = this->prevNewer28;
  }
  if (this->prevNewer28 != 0) {
    this->prevNewer28->nextOlder24 = this->nextOlder24;
  }
  displayName18.~CString();
  delete this;
}

// FUNCTION: IMPERIALISM 0x0054fab0
void TShip::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&resourceType04, 2);
  stream->WriteBytesSlot78(&quantityFlag10, 4);
  stream->WriteBytesSlot78(&ownerNationSlot14, 2);
  stream->streamSlotAc(&displayName18);
  stream->WriteBytesSlot78(&stockLevel1c, 2);
  stream->WriteBytesSlot78(&field34, 4);
  stream->WriteBytesSlot78(&field30, 2);
  short zoneIndex = GetShortAtOffset14OrInvalid(field08);
  stream->WriteBytesSlot78(&zoneIndex, 2);
}

// FUNCTION: IMPERIALISM 0x0054fb50
void TShip::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&resourceType04, 2);
  stream->ReadBytes(&quantityFlag10, 4);
  stream->ReadBytes(&ownerNationSlot14, 2);
  stream->ReadBytes(&displayName18, 0x20);
  stream->ReadBytes(&stockLevel1c, 2);
  stream->ReadBytes(&field34, 4);
  stream->ReadBytes(&field30, 2);
  short zoneIndex = 0;
  stream->ReadBytes(&zoneIndex, 2);
  field08 = reinterpret_cast<TZone*(__cdecl*)(short)>(FindMapActionContextByNodeId)(zoneIndex);
}

// FUNCTION: IMPERIALISM 0x0054fbf0
void __fastcall RegenerateNavyPrimaryOrderDisplayNameUntilUnique(TShip* shipNode) {
  do {
    TAdmiral::GenerateMappedFlavorTextByNationSlotField0C(
        static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[shipNode->resourceType04]),
        &shipNode->displayName18);
    for (TShip* existing = g_pNavyPrimaryOrderListHead; existing != 0;
         existing = existing->nextOlder24) {
      if (existing == shipNode) {
        continue;
      }
      if (CompareAnsiStringsWithMbcsAwareness(
              reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(existing->displayName18)),
              reinterpret_cast<unsigned char*>(
                  (char*)static_cast<LPCSTR>(shipNode->displayName18))) == 0) {
        goto retry;
      }
    }
    return;
  retry:;
  } while (1);
}

// FUNCTION: IMPERIALISM 0x005505c0
void* GetNavyPrimaryOrderListHead(void) {
  return g_pNavyPrimaryOrderListHead;
}

// FUNCTION: IMPERIALISM 0x00550970
short GetIndustryActionCostWeightByResourceType(short resourceType) {
  return g_industryActionCostWeightResCode10[resourceType];
}

// FUNCTION: IMPERIALISM 0x00550b60
int ComputeOrderNodeCompositeEconomicScore(TShip* node) {
  int resourceType = (int)node->resourceType04;
  short quantityField = node->field30;
  int quantityTerm = (int)SignedMod100(quantityField);
  int navyTerm =
      quantityTerm + 5 + g_Navy_Order_Priority_LookupTable_00698118[resourceType * 9] * 10;
  int resolveTerm =
      quantityTerm + 5 + g_Resolve_Map_Order_LookupTable_00698108[resourceType * 9] * 10;
  short stockAt1c = node->stockLevel1c;
  return (SignedDiv10(resolveTerm) +
          (SignedDiv10(navyTerm) +
           g_Calculate_Mission_Order_LookupTable_0069810C[resourceType * 9]) *
              100 +
          (int)stockAt1c) /
         (int)*(short*)(reinterpret_cast<char*>(&g_Task_Force_Order_LookupTable_00698110) +
                        resourceType * 0x24);
}

static int* NavyZoneOrderDescriptorEnabledFlagPtr(short zoneIndex) {
  return reinterpret_cast<int*>(reinterpret_cast<char*>(g_Task_Force_Order_LookupTable_00698110) +
                                static_cast<int>(zoneIndex) * 0x24 + 0x10);
}

static short* NavyZoneOrderDescriptorStockCapPtr(short zoneIndex) {
  return reinterpret_cast<short*>(reinterpret_cast<char*>(g_Task_Force_Order_LookupTable_00698110) +
                                  static_cast<int>(zoneIndex) * 0x24 + 4);
}

// FUNCTION: IMPERIALISM 0x00550e70
short GetResourceDescriptorWeightWord0ByType(short resourceType) {
  return *reinterpret_cast<short*>(&g_ResourceDescriptorWeightWord0Base0069811c +
                                   resourceType * 0x24);
}
