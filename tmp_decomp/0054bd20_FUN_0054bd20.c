
void __thiscall FUN_0054bd20(int param_1,int param_2)

{
  int *piVar1;
  char cVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int *piVar8;
  uint uVar9;
  int iVar10;
  undefined4 *puVar11;
  int *piVar12;
  undefined4 *puVar13;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined1 local_18;
  undefined4 local_14;
  int local_10;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00634dca;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  sVar3 = thunk_GetActiveNationId();
  if (*(int *)(g_pLocalizationTable + 0x44) != 2) {
    if (*(int *)(g_pLocalizationTable + 0x44) == 1) {
      local_1c = 0x74696d65;
      local_18 = thunk_GetActiveNationId();
      local_28 = 0;
      local_24 = 0;
      local_2c = 0x1f;
      local_20 = 0x20;
      thunk_FUN_005420d0(0xfffffffe);
      local_14 = 0x64656875;
      local_10 = param_2;
      thunk_FUN_005e3d40(&local_2c,0);
    }
    piVar1 = (int *)(&g_apNationStates)[param_2];
    if (((piVar1 != (int *)0x0) && ((char)piVar1[0x28] != '\0')) && (param_2 != sVar3)) {
      iVar4 = GenerateThreadLocalRandom15();
      iVar5 = GenerateThreadLocalRandom15();
      uVar6 = GenerateThreadLocalRandom15();
      uVar9 = (int)uVar6 >> 0x1f;
      iVar7 = AllocateWithFallbackHandler(0xb70);
      iVar10 = 0;
      local_4 = 0;
      if (iVar7 != 0) {
        iVar10 = thunk_FUN_004e6b50();
      }
      local_4 = 0xffffffff;
      thunk_FUN_004e6c20(param_2,2,((uVar6 ^ uVar9) - uVar9 & 3 ^ uVar9) - uVar9,iVar5 % 6,iVar4 % 5
                        );
      StringShared__AssignFromPtr((void *)(iVar10 + 4),piVar1 + 1);
      StringShared__AssignFromPtr((void *)(iVar10 + 8),piVar1 + 2);
      *(short *)(iVar10 + 0xc) = (short)piVar1[3];
      *(undefined2 *)(iVar10 + 0xe) = *(undefined2 *)((int)piVar1 + 0xe);
      *(int *)(iVar10 + 0x10) = piVar1[4];
      piVar8 = piVar1 + 5;
      piVar12 = (int *)(iVar10 + 0x14);
      for (iVar4 = 0xb; iVar4 != 0; iVar4 = iVar4 + -1) {
        *piVar12 = *piVar8;
        piVar8 = piVar8 + 1;
        piVar12 = piVar12 + 1;
      }
      *(short *)piVar12 = (short)*piVar8;
      iVar4 = piVar1[0x11];
      piVar1[0x11] = *(int *)(iVar10 + 0x44);
      *(int *)(iVar10 + 0x44) = iVar4;
      piVar8 = piVar1 + 0x12;
      piVar12 = (int *)(iVar10 + 0x48);
      for (iVar4 = 0xf; iVar4 != 0; iVar4 = iVar4 + -1) {
        *piVar12 = *piVar8;
        piVar8 = piVar8 + 1;
        piVar12 = piVar12 + 1;
      }
      *(short *)(iVar10 + 0x84) = (short)piVar1[0x21];
      *(int *)(iVar10 + 0x88) = piVar1[0x22];
      *(int *)(iVar10 + 0x8c) = piVar1[0x23];
      iVar4 = piVar1[0x24];
      piVar1[0x24] = *(int *)(iVar10 + 0x90);
      *(int *)(iVar10 + 0x90) = iVar4;
      *(undefined2 *)(iVar10 + 0xa2) = *(undefined2 *)((int)piVar1 + 0xa2);
      *(short *)(iVar10 + 0xa4) = (short)piVar1[0x29];
      *(undefined2 *)(iVar10 + 0xa6) = *(undefined2 *)((int)piVar1 + 0xa6);
      *(short *)(iVar10 + 0xa8) = (short)piVar1[0x2a];
      *(int *)(iVar10 + 0xac) = piVar1[0x2b];
      *(short *)(iVar10 + 0xb0) = (short)piVar1[0x2c];
      puVar11 = (undefined4 *)((int)piVar1 + 0xb2);
      puVar13 = (undefined4 *)(iVar10 + 0xb2);
      for (iVar4 = 0xb; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar13 = *puVar11;
        puVar11 = puVar11 + 1;
        puVar13 = puVar13 + 1;
      }
      *(undefined2 *)puVar13 = *(undefined2 *)puVar11;
      piVar8 = piVar1 + 0x38;
      piVar12 = (int *)(iVar10 + 0xe0);
      for (iVar4 = 0xb; iVar4 != 0; iVar4 = iVar4 + -1) {
        *piVar12 = *piVar8;
        piVar8 = piVar8 + 1;
        piVar12 = piVar12 + 1;
      }
      *(short *)piVar12 = (short)*piVar8;
      puVar11 = (undefined4 *)((int)piVar1 + 0x10e);
      puVar13 = (undefined4 *)(iVar10 + 0x10e);
      for (iVar4 = 0xb; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar13 = *puVar11;
        puVar11 = puVar11 + 1;
        puVar13 = puVar13 + 1;
      }
      *(undefined2 *)puVar13 = *(undefined2 *)puVar11;
      piVar8 = piVar1 + 0x4f;
      piVar12 = (int *)(iVar10 + 0x13c);
      for (iVar4 = 0xb; iVar4 != 0; iVar4 = iVar4 + -1) {
        *piVar12 = *piVar8;
        piVar8 = piVar8 + 1;
        piVar12 = piVar12 + 1;
      }
      *(short *)piVar12 = (short)*piVar8;
      puVar11 = (undefined4 *)((int)piVar1 + 0x16a);
      puVar13 = (undefined4 *)(iVar10 + 0x16a);
      for (iVar4 = 0xb; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar13 = *puVar11;
        puVar11 = puVar11 + 1;
        puVar13 = puVar13 + 1;
      }
      *(undefined2 *)puVar13 = *(undefined2 *)puVar11;
      piVar8 = piVar1 + 0x66;
      piVar12 = (int *)(iVar10 + 0x198);
      for (iVar4 = 0xb; iVar4 != 0; iVar4 = iVar4 + -1) {
        *piVar12 = *piVar8;
        piVar8 = piVar8 + 1;
        piVar12 = piVar12 + 1;
      }
      *(short *)piVar12 = (short)*piVar8;
      puVar11 = (undefined4 *)((int)piVar1 + 0x1c6);
      puVar13 = (undefined4 *)(iVar10 + 0x1c6);
      for (iVar4 = 0xb; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar13 = *puVar11;
        puVar11 = puVar11 + 1;
        puVar13 = puVar13 + 1;
      }
      *(undefined2 *)puVar13 = *(undefined2 *)puVar11;
      piVar8 = piVar1 + 0x7d;
      piVar12 = (int *)(iVar10 + 500);
      for (iVar4 = 0xb; iVar4 != 0; iVar4 = iVar4 + -1) {
        *piVar12 = *piVar8;
        piVar8 = piVar8 + 1;
        piVar12 = piVar12 + 1;
      }
      *(short *)piVar12 = (short)*piVar8;
      puVar11 = (undefined4 *)((int)piVar1 + 0x222);
      puVar13 = (undefined4 *)(iVar10 + 0x222);
      for (iVar4 = 0xb; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar13 = *puVar11;
        puVar11 = puVar11 + 1;
        puVar13 = puVar13 + 1;
      }
      *(undefined2 *)puVar13 = *(undefined2 *)puVar11;
      piVar8 = piVar1 + 0x94;
      piVar12 = (int *)(iVar10 + 0x250);
      for (iVar4 = 0xb; iVar4 != 0; iVar4 = iVar4 + -1) {
        *piVar12 = *piVar8;
        piVar8 = piVar8 + 1;
        piVar12 = piVar12 + 1;
      }
      *(short *)piVar12 = (short)*piVar8;
      piVar8 = piVar1 + 0xa0;
      piVar12 = (int *)(iVar10 + 0x280);
      for (iVar4 = 0x170; iVar4 != 0; iVar4 = iVar4 + -1) {
        *piVar12 = *piVar8;
        piVar8 = piVar8 + 1;
        piVar12 = piVar12 + 1;
      }
      iVar5 = 0x11;
      *(int *)(iVar10 + 0x840) = piVar1[0x210];
      *(int *)(iVar10 + 0x844) = piVar1[0x211];
      iVar4 = piVar1[0x212];
      piVar1[0x212] = *(int *)(iVar10 + 0x848);
      *(int *)(iVar10 + 0x848) = iVar4;
      iVar4 = piVar1[0x213];
      piVar1[0x213] = *(int *)(iVar10 + 0x84c);
      *(int *)(iVar10 + 0x84c) = iVar4;
      piVar8 = piVar1 + 0x214;
      do {
        iVar4 = *piVar8;
        *piVar8 = *(int *)((iVar10 - (int)piVar1) + (int)piVar8);
        *(int *)((iVar10 - (int)piVar1) + (int)piVar8) = iVar4;
        piVar8 = piVar8 + 1;
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
      iVar4 = piVar1[0x225];
      piVar1[0x225] = *(int *)(iVar10 + 0x894);
      *(int *)(iVar10 + 0x894) = iVar4;
      if (iVar4 != 0) {
        *(int *)(iVar4 + 0xac) = iVar10;
      }
      iVar4 = piVar1[0x226];
      piVar1[0x226] = *(int *)(iVar10 + 0x898);
      *(int *)(iVar10 + 0x898) = iVar4;
      iVar4 = piVar1[0x227];
      piVar1[0x227] = *(int *)(iVar10 + 0x89c);
      *(int *)(iVar10 + 0x89c) = iVar4;
      piVar8 = piVar1 + 0x228;
      piVar12 = (int *)(iVar10 + 0x8a0);
      for (iVar4 = 5; iVar4 != 0; iVar4 = iVar4 + -1) {
        *piVar12 = *piVar8;
        piVar8 = piVar8 + 1;
        piVar12 = piVar12 + 1;
      }
      *(short *)piVar12 = (short)*piVar8;
      *(undefined1 *)((int)piVar12 + 2) = *(undefined1 *)((int)piVar8 + 2);
      *(int *)(iVar10 + 0x8c8) = piVar1[0x232];
      *(int *)(iVar10 + 0x8cc) = piVar1[0x233];
      *(int *)(iVar10 + 0x8d0) = piVar1[0x234];
      *(char *)(iVar10 + 0x8d4) = (char)piVar1[0x235];
      puVar11 = (undefined4 *)((int)piVar1 + 0x8d6);
      puVar13 = (undefined4 *)(iVar10 + 0x8d6);
      for (iVar4 = 6; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar13 = *puVar11;
        puVar11 = puVar11 + 1;
        puVar13 = puVar13 + 1;
      }
      *(undefined2 *)puVar13 = *(undefined2 *)puVar11;
      *(int *)(iVar10 + 0x900) = piVar1[0x240];
      *(char *)(iVar10 + 0x904) = (char)piVar1[0x241];
      (&g_apNationStates)[param_2] = iVar10;
      (&g_pTerrainTypeDescriptorTable)[param_2] = iVar10;
      thunk_FUN_004e83d0();
      iVar4 = 0;
      do {
        cVar2 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x44))(param_2,iVar4);
        if (cVar2 != '\0') {
          *(undefined1 *)(iVar4 + iVar10 + 0x8a0) = 1;
        }
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x17);
      iVar4 = *piVar1;
      *(undefined2 *)(g_pLocalizationTable + 0xda + param_2 * 2) = 2;
      (**(code **)(iVar4 + 0x1c))();
    }
    if ((*(int *)(g_pLocalizationTable + 0x44) == 1) && (param_2 != sVar3)) {
      thunk_FUN_005e42c0(*(undefined4 *)(param_1 + 0x48 + param_2 * 4));
    }
  }
  if ((*(int *)(g_pLocalizationTable + 0x44) == 2) && ((&g_apNationStates)[param_2] != 0)) {
    *(undefined1 *)((&g_apNationStates)[param_2] + 0xa0) = 0;
  }
  *(undefined4 *)(param_1 + 0x48 + param_2 * 4) = 0;
  *(undefined4 *)(param_1 + 0xbc + param_2 * 4) = 0x756e6173;
  thunk_FUN_0054cc00(param_2);
  if ((*(int *)(g_pLocalizationTable + 0x44) == 1) &&
     (*(uint *)(param_1 + 0xe8) = *(uint *)(param_1 + 0xe8) & ~(1 << ((byte)param_2 & 0x1f)),
     *(int *)(g_pLocalizationTable + 0x44) == 1)) {
    local_1c = 0x74696d65;
    local_18 = thunk_GetActiveNationId();
    local_14 = *(undefined4 *)(param_1 + 0xe8);
    local_28 = 0;
    local_2c = 1;
    local_24 = 0;
    local_20 = 0x1c;
    thunk_FUN_005e3d40(&local_2c,0);
    if ((*(int *)(param_1 + 0xe8) == 0) && (*(int *)(param_1 + 0xf0) != -1)) {
      thunk_FUN_00543910();
    }
  }
  *unaff_FS_OFFSET = uStack_c;
  return;
}

