
/* Rebuilds one secondary/extended nation slot object (minor nation / extra slot range).
   
   Behavior:
   - For slots < 7, clears DAT_006A4280[slot].
   - For valid extended slots, frees prior object, allocates class based on flow mode, stores into
   DAT_006A4280 and DAT_006A4310.
   - In active mode, issues initialization callbacks and creates related military recruit order
   objects.
   
   Used by RebuildNationStateSlotsAndAvailability via vtable +0x30 dispatch. */

void __thiscall RebuildSecondaryNationStateForSlot(int param_1,undefined4 param_2)

{
  undefined2 uVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  undefined4 *puVar5;
  int iVar6;
  short sVar7;
  int iVar8;
  int *piVar9;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 uStack_4;
  
  local_c = *unaff_FS_OFFSET;
  uStack_4 = 0xffffffff;
  puStack_8 = &LAB_00636ede;
  *unaff_FS_OFFSET = &local_c;
  sVar7 = (short)param_2;
  if (sVar7 < 7) {
    (&DAT_006a4280)[sVar7] = 0;
    goto LAB_0057d6fe;
  }
  iVar8 = (int)sVar7;
  iVar4 = *(int *)(param_1 + 0x34) + 7;
  if (iVar8 < iVar4) {
    iVar2 = *(int *)(param_1 + 0x44);
    if (iVar2 != 2) {
      if (iVar8 < iVar4) {
        piVar9 = (int *)0x0;
        if ((int *)(&DAT_006a4280)[iVar8] != (int *)0x0) {
          (**(code **)(*(int *)(&DAT_006a4280)[iVar8] + 0x1c))();
        }
        (&DAT_006a4280)[iVar8] = 0;
        (&g_pTerrainTypeDescriptorTable)[iVar8] = 0;
        iVar4 = AllocateWithFallbackHandler(0x2dc);
        uStack_4 = 1;
        if (iVar4 != 0) {
          piVar9 = (int *)thunk_FUN_004e3710();
        }
        uStack_4 = 0xffffffff;
        thunk_FUN_004e3830(param_2);
        cVar3 = DAT_006a43f0;
        (&DAT_006a4280)[iVar8] = piVar9;
        (&g_pTerrainTypeDescriptorTable)[iVar8] = piVar9;
        if (cVar3 == '\0') {
          iVar4 = *piVar9;
          (**(code **)(iVar4 + 0x30))();
          iVar8 = 2;
          uVar1 = *(undefined2 *)
                   (*(int *)(g_pGlobalMapState + 0xc) + 0x14 + (short)piVar9[0x22] * 0x24);
          do {
            iVar6 = AllocateWithFallbackHandler(0x44);
            uStack_4 = 2;
            if (iVar6 == 0) {
              piVar9 = (int *)0x0;
            }
            else {
              piVar9 = (int *)InitializeMilitaryUnitOrderObject();
            }
            uStack_4 = 0xffffffff;
            InitializeMilitaryRecruitOrderState
                      (2,CONCAT22((short)((uint)iVar2 >> 0x10),uVar1),param_2,0);
            (**(code **)(*piVar9 + 0x34))(2,0xffffffff);
            iVar8 = iVar8 + -1;
          } while (iVar8 != 0);
          (**(code **)(iVar4 + 0x3c))();
        }
        goto LAB_0057d6fe;
      }
      goto LAB_0057d6de;
    }
    if ((int *)(&DAT_006a4280)[iVar8] != (int *)0x0) {
      (**(code **)(*(int *)(&DAT_006a4280)[iVar8] + 0x1c))();
    }
    (&DAT_006a4280)[iVar8] = 0;
    (&g_pTerrainTypeDescriptorTable)[iVar8] = 0;
    puVar5 = (undefined4 *)AllocateWithFallbackHandler(0x2dc);
    uStack_4 = 0;
    if (puVar5 == (undefined4 *)0x0) {
      puVar5 = (undefined4 *)0x0;
    }
    else {
      thunk_FUN_004e3710();
      *puVar5 = &PTR_LAB_0065bde0;
    }
    uStack_4 = 0xffffffff;
    thunk_FUN_004e3830(param_2);
  }
  else {
LAB_0057d6de:
    puVar5 = (undefined4 *)0x0;
    if ((int *)(&DAT_006a4280)[iVar8] != (int *)0x0) {
      (**(code **)(*(int *)(&DAT_006a4280)[iVar8] + 0x1c))();
    }
  }
  (&DAT_006a4280)[iVar8] = puVar5;
  (&g_pTerrainTypeDescriptorTable)[iVar8] = puVar5;
LAB_0057d6fe:
  *unaff_FS_OFFSET = local_c;
  return;
}

