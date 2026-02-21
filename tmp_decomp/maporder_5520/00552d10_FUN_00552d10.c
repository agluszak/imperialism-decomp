
void __thiscall FUN_00552d10(int param_1,int *param_2)

{
  code *pcVar1;
  char cVar2;
  short sVar3;
  int iVar4;
  undefined4 uVar5;
  short *psVar6;
  int *piVar7;
  int iStack_54;
  short *psStack_4c;
  int *piStack_48;
  int *piStack_44;
  int iStack_40;
  undefined1 *puStack_3c;
  undefined4 uStack_38;
  int *piStack_34;
  undefined4 uStack_30;
  int iStack_2c;
  int *piStack_28;
  
  piStack_28 = param_2;
  iStack_2c = 0x552d27;
  thunk_HandleCityDialogNoOpSlot18();
  iStack_2c = param_1 + 4;
  piStack_28 = (int *)0x4;
  pcVar1 = *(code **)(*param_2 + 0x3c);
  uStack_30 = 0x552d36;
  (*pcVar1)();
  uStack_30 = 4;
  uStack_38 = 0x552d40;
  piStack_34 = (int *)(param_1 + 8);
  (*pcVar1)();
  puStack_3c = &stack0xffffffdc;
  uStack_38 = 2;
  iStack_40 = 0x552d4b;
  (*pcVar1)();
  if (*(int *)(param_1 + 8) == 5) {
    iVar4 = *(int *)(g_pGlobalMapState + 0x10) + (short)iStack_2c * 0xa8;
  }
  else {
    iStack_40 = iStack_2c;
    piStack_44 = (int *)0x552d77;
    iVar4 = thunk_FUN_0055f100();
  }
  piStack_44 = &iStack_2c;
  iStack_40 = 2;
  *(int *)(param_1 + 0xc) = iVar4;
  piStack_48 = (int *)0x552d88;
  (*pcVar1)();
  piStack_48 = piStack_34;
  psStack_4c = (short *)0x552d92;
  uVar5 = thunk_FUN_0055f100();
  piVar7 = (int *)(param_1 + 0x1c);
  *(undefined4 *)(param_1 + 0x18) = uVar5;
  piStack_48 = (int *)0x2;
  psStack_4c = (short *)piVar7;
  piStack_28 = piVar7;
  (*pcVar1)();
  (*pcVar1)();
  piStack_34 = (int *)(param_1 + 0x30);
  (*pcVar1)(piStack_34,2);
  (*pcVar1)(&psStack_4c,2);
  iStack_54 = param_1 + 0x25;
  if ((short)param_1 != -0x26) {
    do {
      (*pcVar1)(&psStack_4c,2);
      (*pcVar1)(&piStack_44,2);
      iVar4 = g_pNavyPrimaryOrderList;
      for (psVar6 = psStack_4c; (iVar4 != 0 && ((short)psVar6 != 0));
          psVar6 = (short *)((int)psVar6 + -1)) {
        iVar4 = *(int *)(iVar4 + 0x24);
      }
      if ((0x10 < DAT_00695278) || (*(int *)(iVar4 + 0xc) == 0)) {
        thunk_FUN_00553bc0(iVar4);
        cVar2 = (char)puStack_3c;
        piVar7 = piRam00000011;
        if ((piRam00000011 != (int *)0x0) && (*piRam00000011 != iVar4)) {
          piVar7 = FindMissionOrderNodeById((void *)piRam00000011[1],iVar4);
        }
        if ((piVar7 != (int *)0x0) && (*(char *)(piVar7 + 3) = cVar2, cVar2 != '\0')) {
          *(undefined4 *)(iVar4 + 0x34) = 0;
        }
      }
      sVar3 = (short)iStack_54;
      iStack_54 = iStack_54 + -1;
      piVar7 = piStack_48;
    } while (sVar3 != 0);
  }
  sVar3 = thunk_GetActiveNationId();
  if ((short)*piStack_44 == -1) {
    if (*(short *)piVar7 != sVar3) {
      return;
    }
  }
  else {
    if (*(short *)piVar7 != sVar3) {
      *(short *)piStack_44 = -1;
      return;
    }
    if (-1 < *(char *)(*(int *)(g_pGlobalMapState + 0xc) + 0x16 + (short)*piStack_44 * 0x24)) {
      return;
    }
  }
  thunk_FUN_00556410();
  return;
}

