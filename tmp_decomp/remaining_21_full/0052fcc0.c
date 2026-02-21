// 0x0052fcc0 FUN_0052fcc0\n\n
void __fastcall FUN_0052fcc0(int param_1)

{
  short sVar1;
  int iVar2;
  undefined4 *puVar3;
  
  *(undefined2 *)(param_1 + 0x12) = 0;
  *(undefined2 *)(param_1 + 0x14) = 0;
  *(undefined2 *)(param_1 + 0x10) = 0xfff6;
  sVar1 = (**(code **)(**(int **)(param_1 + 4) + 0x74))();
  if (sVar1 == 0) {
    *(short *)(param_1 + 0x18) = *(short *)(param_1 + 0x18) + 1;
  }
  puVar3 = (undefined4 *)(param_1 + 0x1e);
  for (iVar2 = 8; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = 0;
  return;
}

