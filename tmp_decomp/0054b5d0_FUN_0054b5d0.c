
void FUN_0054b5d0(char param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined2 *puVar3;
  undefined2 *puVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  int iVar9;
  int local_6f0;
  undefined4 local_6e4;
  undefined4 local_6e0;
  undefined4 local_6dc;
  undefined4 local_6d8;
  undefined4 local_6d4;
  undefined1 local_6d0;
  undefined2 local_6cc;
  undefined4 local_6c8;
  undefined4 local_6c4;
  undefined2 local_6c0 [23];
  undefined2 local_692 [23];
  undefined2 local_664 [23];
  undefined2 local_636 [23];
  undefined2 local_608 [24];
  undefined4 local_5d8 [368];
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined1 local_c;
  undefined4 local_8;
  undefined1 local_4;
  
  local_6d4 = 0x74696d65;
  local_6d0 = thunk_GetActiveNationId();
  local_6e4 = 0x15;
  local_6e0 = 0;
  local_6d8 = 0x6e4;
  if (param_1 == '\0') {
    local_6dc = *(undefined4 *)(g_pGameFlowState + 0x48 + param_2 * 4);
  }
  else {
    local_6dc = 0xffffffff;
  }
  local_6cc = (undefined2)param_2;
  iVar1 = (&g_apNationStates)[param_2];
  puVar7 = local_5d8;
  local_6c8 = *(undefined4 *)(iVar1 + 0x10);
  local_6f0 = 0x17;
  local_6c4 = *(undefined4 *)(iVar1 + 0xac);
  puVar5 = (undefined4 *)(iVar1 + 0x280);
  puVar4 = local_692;
  puVar3 = (undefined2 *)(iVar1 + 0x13c);
  do {
    iVar9 = 0x10;
    puVar4[-0x17] = puVar3[-0x17];
    *puVar4 = *puVar3;
    puVar4[0x17] = puVar3[0x17];
    puVar4[0x2e] = puVar3[0x2e];
    puVar4[0x45] = puVar3[0x45];
    puVar6 = puVar5;
    puVar8 = puVar7;
    do {
      uVar2 = *puVar6;
      puVar6 = puVar6 + 0x17;
      *puVar8 = uVar2;
      puVar8 = puVar8 + 0x17;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
    puVar7 = puVar7 + 1;
    puVar5 = puVar5 + 1;
    local_6f0 = local_6f0 + -1;
  } while (local_6f0 != 0);
  local_18 = *(undefined4 *)(iVar1 + 0x840);
  local_14 = *(undefined4 *)(iVar1 + 0x844);
  local_10 = *(undefined4 *)(iVar1 + 0x8f0);
  local_c = *(undefined1 *)(iVar1 + 0x8f4);
  local_8 = *(undefined4 *)(iVar1 + 0x8f8);
  local_4 = *(undefined1 *)(iVar1 + 0x8fc);
  thunk_FUN_005e3d40(&local_6e4,0);
  return;
}

