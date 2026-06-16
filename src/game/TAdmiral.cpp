#include "game/TAdmiral.h"

#include "game/mapped_flavor_text.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

#include "game/diplomacy_globals.h"
#include "game/TMinor.h"
extern "C" TAdmiral* g_pNavySecondaryOrderListHead = 0;
extern "C" char g_pClassDescTAdmiral = 0;

#include "game/CString.h"

// FUNCTION: IMPERIALISM 0x004d7eb0
void __fastcall TAdmiral::GenerateMappedFlavorTextByNationSlotField0C(TMinor* terrainDescriptor,
                                                                      CString* dest) {
  GenerateMappedFlavorTextByTableSlot(dest, terrainDescriptor->nationSlot);
}
// FUNCTION: IMPERIALISM 0x00551410
CRuntimeClass* TAdmiral::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(&g_pClassDescTAdmiral);
}

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
        static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[terrainType]),
                                                &displayName);
    for (TAdmiral* node = g_pNavySecondaryOrderListHead; node != 0; node = node->next) {
      if (node == this) {
        continue;
      }
      if (CompareAnsiStringsWithMbcsAwareness(
              reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(node->displayName)),
              reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(this->displayName))) ==
          0) {
        this->DestroyAndUnlinkNavySecondaryOrderNode();
      }
    }
  }
}

// SYNTHETIC: IMPERIALISM 0x00551550
// TAdmiral::`scalar deleting destructor'

#include "game/TMapOrderEntry.h"

static void RecomputeMapOrderOwnerActiveSelection(TMapOrderEntryOwnerContext* ownerContext) {
  if (ownerContext == 0) {
    return;
  }
  ownerContext->active_node = 0;
  for (TMapOrderChildLinkNode* link = ownerContext->head; link != 0; link = link->next) {
    TMapOrderEntry* activeEntry = reinterpret_cast<TMapOrderEntry*>(ownerContext->active_node);
    int preferred = reinterpret_cast<TMapOrderEntry*>(link->object_ptr)
                        ->SelectPreferredMapOrderEntryByPriorityRules(activeEntry, 0);
    ownerContext->active_node = preferred;
  }
}

static void ClearPrimaryOrderBacklink(void* primaryOrderNode) {
  if (primaryOrderNode == 0) {
    return;
  }
  *reinterpret_cast<void**>(reinterpret_cast<char*>(primaryOrderNode) + 0x20) = 0;
  TMapOrderEntryOwnerContext* ownerContext = *reinterpret_cast<TMapOrderEntryOwnerContext**>(
      reinterpret_cast<char*>(primaryOrderNode) + 0xc);
  RecomputeMapOrderOwnerActiveSelection(ownerContext);
}

// FUNCTION: IMPERIALISM 0x00551580
TAdmiral::~TAdmiral() {}

// FUNCTION: IMPERIALISM 0x005515d0
void TAdmiral::DestroyAndUnlinkNavySecondaryOrderNode() {
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

// FUNCTION: IMPERIALISM 0x00552250
void TAdmiral::SetTaskForcePrimaryOrderLinkAndRefreshChildBacklinks(void* primaryOrderNode) {
  if (this->field_8 != 0) {
    ClearPrimaryOrderBacklink(reinterpret_cast<void*>(this->field_8));
  }
  this->field_8 = reinterpret_cast<int>(primaryOrderNode);
  if (primaryOrderNode != 0) {
    *reinterpret_cast<void**>(reinterpret_cast<char*>(primaryOrderNode) + 0x20) = this;
    TMapOrderEntryOwnerContext* ownerContext = *reinterpret_cast<TMapOrderEntryOwnerContext**>(
        reinterpret_cast<char*>(primaryOrderNode) + 0xc);
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
