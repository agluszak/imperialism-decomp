#include "game/TAdmiral.h"

#include "game/mapped_flavor_text.h"
#include "game/TShip.h"
#include "game/TTaskForce.h"
#include "game/global_data_tables.h"
#include "game/TMinor.h"
extern "C" TAdmiral* g_pNavySecondaryOrderListHead = 0;

#include "game/CString.h"

// FUNCTION: IMPERIALISM 0x004d7eb0
void __fastcall TAdmiral::GenerateMappedFlavorTextByNationSlotField0C(TMinor* terrainDescriptor,
                                                                      CString* dest) {
  GenerateMappedFlavorTextByTableSlot(dest, terrainDescriptor->nationSlot);
}

// SYNTHETIC: IMPERIALISM 0x005512d0
// TAdmiral::CreateObject

// SYNTHETIC: IMPERIALISM 0x00551410
// TAdmiral::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAdmiral, TObject)

// FUNCTION: IMPERIALISM 0x00551430
TAdmiral::TAdmiral(short terrainTypeIndex)
    : terrainType(terrainTypeIndex), primaryOrderNode08(0), displayName(), field_10(0),
      next(g_pNavySecondaryOrderListHead), prev(0) {
  g_pNavySecondaryOrderListHead = this;
  if (next != 0) {
    next->prev = this;
  }
  if (static_cast<unsigned short>(terrainType) != 0xffff) {
    GenerateMappedFlavorTextByNationSlotField0C(
        static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[terrainType]), &displayName);
    for (TAdmiral* node = g_pNavySecondaryOrderListHead; node != 0; node = node->next) {
      if (node == this) {
        continue;
      }
      if (_mbscmp(reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(node->displayName)),
                  reinterpret_cast<unsigned char*>(
                      (char*)static_cast<LPCSTR>(this->displayName))) == 0) {
        this->Free();
      }
    }
  }
}

// SYNTHETIC: IMPERIALISM 0x00551550
// TAdmiral::`scalar deleting destructor'

// Inline-expanded into every caller in the original (0x552250 and 0x551850 carry the
// body verbatim, and 0x5b0500 in another TU still CALLs 0x552250 itself), so it must be
// `inline` for MSVC500 /Ob1 to reproduce that. Callers spell the clear-backlink steps
// out on `this->primaryOrderNode08` directly (the original re-reads the member after
// the +0x20 store), so there is no ClearPrimaryOrderBacklink helper.
static inline void RecomputeMapOrderOwnerActiveSelection(TTaskForce* ownerContext) {
  if (ownerContext == 0) {
    return;
  }
  ownerContext->activeChildEntry = 0;
  for (TMapOrderChildLinkNode* link = ownerContext->childOrderList; link != 0; link = link->next) {
    TTaskForce* activeEntry = ownerContext->activeChildEntry;
    ownerContext->activeChildEntry =
        link->object_ptr->SelectPreferredMapOrderEntryByPriorityRules(activeEntry, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00551580
TAdmiral::~TAdmiral() {}

// FUNCTION: IMPERIALISM 0x005515d0
void TAdmiral::Free() {
  if (this->prev != 0) {
    this->prev->next = this->next;
  } else {
    g_pNavySecondaryOrderListHead = this->next;
  }
  if (this->next != 0) {
    this->next->prev = this->prev;
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x00551670
void TAdmiral::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00551700
void TAdmiral::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00551850
void TAdmiral::SelectNavyPrimaryOrderByNationAndRecomputePreferredChild() {
  if (this->primaryOrderNode08 != 0) {
    this->primaryOrderNode08->admiralBacklink20 = 0;
    RecomputeMapOrderOwnerActiveSelection(this->primaryOrderNode08->ownerOrderEntry0c);
  }
  this->primaryOrderNode08 = 0;

  TShip* best = 0;
  for (TShip* node = g_pNavyPrimaryOrderListHead; node != 0; node = node->nextOlder24) {
    if (node->ownerNationSlot14 == this->terrainType) {
      // The original dispatches TTaskForce's 0x550670 __thiscall on the TShip-shaped
      // primary-order node (shared +0x04/+0x1c/+0x30 prefix -- same receiver pun the
      // GetNavyOrderNormalizationBaseByResourceType comment documents).
      best = reinterpret_cast<TShip*>(
          reinterpret_cast<TTaskForce*>(node)->SelectPreferredMapOrderEntryByPriorityRules(
              reinterpret_cast<TTaskForce*>(best), 1));
    }
  }

  if (this->primaryOrderNode08 != 0) {
    this->primaryOrderNode08->admiralBacklink20 = 0;
    RecomputeMapOrderOwnerActiveSelection(this->primaryOrderNode08->ownerOrderEntry0c);
  }
  this->primaryOrderNode08 = best;
  if (best != 0) {
    best->admiralBacklink20 = this;
    RecomputeMapOrderOwnerActiveSelection(this->primaryOrderNode08->ownerOrderEntry0c);
  }
  if (best == 0) {
    this->Free();
  }
}

// FUNCTION: IMPERIALISM 0x00552250
void TAdmiral::SetTaskForcePrimaryOrderLinkAndRefreshChildBacklinks(TShip* primaryOrderNode) {
  if (this->primaryOrderNode08 != 0) {
    this->primaryOrderNode08->admiralBacklink20 = 0;
    RecomputeMapOrderOwnerActiveSelection(this->primaryOrderNode08->ownerOrderEntry0c);
  }
  this->primaryOrderNode08 = primaryOrderNode;
  if (primaryOrderNode != 0) {
    primaryOrderNode->admiralBacklink20 = this;
    RecomputeMapOrderOwnerActiveSelection(this->primaryOrderNode08->ownerOrderEntry0c);
  }
}

// FUNCTION: IMPERIALISM 0x00552450
void TAdmiral::RemoveDuplicateNavySecondaryOrdersByDisplayName() {
  GenerateMappedFlavorTextByNationSlotField0C(
      static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[this->terrainType]), &this->displayName);
  for (TAdmiral* node = g_pNavySecondaryOrderListHead; node != 0; node = node->next) {
    if (node == this) {
      continue;
    }
    if (_mbscmp(reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(node->displayName)),
                reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(this->displayName))) ==
        0) {
      this->RemoveDuplicateNavySecondaryOrdersByDisplayName();
    }
  }
}
