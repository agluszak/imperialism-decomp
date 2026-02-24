#include "game/input_state.h"

typedef short(__cdecl* PFN_VtblGetSlot)(void* this_ptr);
typedef void(__cdecl* PFN_VtblSetUiFlag)(void* this_ptr, int state_flag);

unsigned int __cdecl thunk_GetActiveNationId(void);
undefined4 thunk_GetNavyPrimaryOrderListHead(void);
undefined4 thunk_SetMapTileStateByteAndNotifyObserver(void);

static const unsigned int g_addrGlobalMapState = 0x006a43d4;

// FUNCTION: IMPERIALISM 0x0055fc40
void InputState::HandleKeyDown(int key_id) {
  int iVar2;
  short sVarSlotId;
  short sVarActiveSlot;
  void* pvNode;
  int nSlotsRemaining;
  bool bSlotIsActive;
  unsigned int uSlotIndex;
  unsigned int uSlotCountLocal;
  int* piSlotEntry;
  int iGlobalMapState;

  if ((active_key_mask & (1U << ((unsigned char)key_id & 0x1f))) == 0) {
    active_key_mask = active_key_mask | (1U << ((unsigned char)key_id & 0x1f));
    sVarSlotId = (short)thunk_GetActiveNationId();

    if ((active_key_mask & (1U << ((unsigned char)sVarSlotId & 0x1f))) == 0) {
      uSlotCountLocal = slot_count;
      uSlotIndex = 0;
      if (uSlotCountLocal != 0) {
        do {
          if (uSlotIndex < uSlotCountLocal) {
            piSlotEntry = (int*)(slot_table_ptr + uSlotIndex * 4);
          } else {
            piSlotEntry = (int*)0;
          }
          if (*(char*)*piSlotEntry == (char)sVarSlotId) {
            goto LAB_0055fcae;
          }
          uSlotIndex = uSlotIndex + 1;
        } while (uSlotIndex < uSlotCountLocal);
      }
      bSlotIsActive = false;
    } else {
    LAB_0055fcae:
      bSlotIsActive = true;
    }

    if (bSlotIsActive) {
      iVar2 = *(int*)this;
      if (sVarSlotId == (short)key_id) {
        ((PFN_VtblSetUiFlag) * (int*)(iVar2 + 0x58))(this, 1);
        key_id = sVarSlotId + 1;
        nSlotsRemaining = 6;
        do {
          if ((active_key_mask & (1U << ((unsigned char)(key_id % 7) & 0x1f))) != 0) {
            sVarSlotId = ((PFN_VtblGetSlot) * (int*)(iVar2 + 0x50))(this);
            iGlobalMapState = *(int*)g_addrGlobalMapState;
            reinterpret_cast<void(__cdecl*)(void*, void*)>(
                thunk_SetMapTileStateByteAndNotifyObserver)((void*)iGlobalMapState,
                                                            (void*)(int)sVarSlotId);
            *(undefined2*)(*(int*)(iGlobalMapState + 0xc) + 0x1a + sVarSlotId * 0x24) = 0xffff;
          }
          key_id = key_id + 1;
          nSlotsRemaining = nSlotsRemaining - 1;
        } while (nSlotsRemaining != 0);
      } else {
        sVarSlotId = ((PFN_VtblGetSlot) * (int*)(*(int*)this + 0x50))(this);
        iGlobalMapState = *(int*)g_addrGlobalMapState;
        reinterpret_cast<void(__cdecl*)(void*, void*)>(thunk_SetMapTileStateByteAndNotifyObserver)(
            (void*)iGlobalMapState, (void*)(int)sVarSlotId);
        *(undefined2*)(*(int*)(iGlobalMapState + 0xc) + 0x1a + sVarSlotId * 0x24) = 0xffff;
      }
    }
  }

  sVarActiveSlot = (short)thunk_GetActiveNationId();
  if (sVarActiveSlot == -1) {
    sVarActiveSlot = (short)thunk_GetActiveNationId();
  }

  if ((active_key_mask & (1U << ((unsigned char)sVarActiveSlot & 0x1f))) != 0) {
    for (pvNode = (void*)thunk_GetNavyPrimaryOrderListHead(); pvNode != (void*)0;
         pvNode = *(void**)((int)pvNode + 0x24)) {
      if (((*(void**)((int)pvNode + 8) == this) &&
           (*(short*)((int)pvNode + 0x14) == sVarActiveSlot)) &&
          (*(int*)((int)pvNode + 0xc) == 0)) {
        ((PFN_VtblSetUiFlag) * (int*)(*(int*)this + 0x58))(this, 1);
        return;
      }
    }
  }
  ((PFN_VtblSetUiFlag) * (int*)(*(int*)this + 0x58))(this, 0);
}
