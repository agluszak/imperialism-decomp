
void __fastcall FUN_004dd4e0(int *param_1)

{
  bool bVar1;
  char cVar2;
  short sVar3;
  short sVar4;
  undefined2 extraout_var;
  short *psVar5;
  undefined4 unaff_EBX;
  int *piVar6;
  int iVar7;
  undefined4 *unaff_FS_OFFSET;
  int iStack_14;
  code *local_10;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 uStack_4;
  
  uStack_c = *unaff_FS_OFFSET;
  uStack_4 = 0xffffffff;
  puStack_8 = &LAB_0063225a;
  *unaff_FS_OFFSET = &uStack_c;
  if ((char)param_1[0x28] == '\0') {
    (**(code **)(*(int *)param_1[0x25] + 0x8c))();
  }
  else {
    bVar1 = false;
    iVar7 = 7;
    local_10 = *(code **)(*param_1 + 0x7c);
    do {
      sVar3 = (*local_10)(iVar7);
      if (sVar3 < 0) {
        bVar1 = true;
      }
      iVar7 = iVar7 + 1;
    } while ((short)iVar7 < 0xc);
    if (bVar1) {
      sVar3 = -1;
      iVar7 = AllocateWithFallbackHandler(0x18);
      piVar6 = (int *)0x0;
      uStack_4 = 0;
      if (iVar7 != 0) {
        piVar6 = (int *)thunk_FUN_004ee540();
      }
      uStack_4 = 0xffffffff;
      thunk_FUN_004ee5c0();
      (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x88))
                (CONCAT22(extraout_var,(short)param_1[3]),1,piVar6);
      iStack_14 = 7;
      do {
        sVar4 = (*local_10)(iStack_14);
        if (sVar4 < 0) {
          iVar7 = piVar6[2];
          if (sVar3 < 0) {
            do {
              if ((short)iVar7 < 1) break;
              psVar5 = (short *)(**(code **)(*piVar6 + 0x2c))((int)(short)iVar7);
              sVar3 = *psVar5;
              iVar7 = iVar7 + -1;
              if (*(char *)((&g_apNationStates)[sVar3] + 0xa0) != '\0') {
                sVar3 = -1;
              }
            } while (sVar3 < 0);
            if (sVar3 < 0) goto LAB_004dd5f5;
          }
          (**(code **)(*(int *)(&g_apNationStates)[sVar3] + 0x19c))
                    (iStack_14,CONCAT22(sVar3 >> 0xf,(short)param_1[3]));
        }
LAB_004dd5f5:
        iStack_14 = iStack_14 + 1;
      } while ((short)iStack_14 < 0xc);
      if (piVar6 != (int *)0x0) {
        (**(code **)(*piVar6 + 0x24))();
      }
    }
    sVar3 = (*local_10)(5);
    if (sVar3 == -1) {
      bVar1 = false;
      while (!bVar1) {
        iVar7 = GenerateThreadLocalRandom15();
        iStack_14 = iVar7 % 7;
        cVar2 = thunk_IsNationSlotEligibleForEventProcessing(iStack_14);
        if (((cVar2 != '\0') &&
            (cVar2 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x44))
                               (iStack_14,(short)param_1[3]), cVar2 == '\0')) &&
           (iStack_14 != (short)param_1[3])) {
          bVar1 = true;
        }
      }
      (**(code **)(*(int *)(&g_apNationStates)[iStack_14] + 0x19c))(5,(short)param_1[3]);
      *unaff_FS_OFFSET = unaff_EBX;
      return;
    }
  }
  *unaff_FS_OFFSET = local_10;
  return;
}

