#include "game/TAdmiral.h"

#include "game/mapped_flavor_text.h"
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
    : terrainType(terrainTypeIndex), field_8(0), displayName(), field_10(0),
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
      if (CompareAnsiStringsWithMbcsAwareness(
              reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(node->displayName)),
              reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(this->displayName))) ==
          0) {
        this->Free();
      }
    }
  }
}

// SYNTHETIC: IMPERIALISM 0x00551550
// TAdmiral::`scalar deleting destructor'

static void RecomputeMapOrderOwnerActiveSelection(TTaskForce* ownerContext) {
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

static void ClearPrimaryOrderBacklink(void* primaryOrderNode) {
  if (primaryOrderNode == 0) {
    return;
  }
  *reinterpret_cast<void**>(reinterpret_cast<char*>(primaryOrderNode) + 0x20) = 0;
  // The owner pointer at +0xc follows the same node-prefix convention
  // TTaskForce::owner/RemoveNode use (bd 1uj.16.1 merge); primaryOrderNode itself is a
  // TShip-shaped node here, not a TTaskForce, so it stays raw/opaque (void*).
  TTaskForce* ownerContext =
      *reinterpret_cast<TTaskForce**>(reinterpret_cast<char*>(primaryOrderNode) + 0xc);
  RecomputeMapOrderOwnerActiveSelection(ownerContext);
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

// FUNCTION: IMPERIALISM 0x00552250
void TAdmiral::SetTaskForcePrimaryOrderLinkAndRefreshChildBacklinks(void* primaryOrderNode) {
  if (this->field_8 != 0) {
    ClearPrimaryOrderBacklink(reinterpret_cast<void*>(this->field_8));
  }
  this->field_8 = reinterpret_cast<int>(primaryOrderNode);
  if (primaryOrderNode != 0) {
    *reinterpret_cast<void**>(reinterpret_cast<char*>(primaryOrderNode) + 0x20) = this;
    TTaskForce* ownerContext =
        *reinterpret_cast<TTaskForce**>(reinterpret_cast<char*>(primaryOrderNode) + 0xc);
    RecomputeMapOrderOwnerActiveSelection(ownerContext);
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
    if (CompareAnsiStringsWithMbcsAwareness(
            reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(node->displayName)),
            reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(this->displayName))) == 0) {
      this->RemoveDuplicateNavySecondaryOrdersByDisplayName();
    }
  }
}
