
void __fastcall FUN_00500f10(int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  iVar3 = 1;
  piVar2 = *(int **)(param_1 + 4);
  if (0 < piVar2[2]) {
    do {
      iVar1 = (**(code **)(*piVar2 + 0x2c))(iVar3);
      *(undefined2 *)(iVar1 + 8) = 0;
      *(undefined1 *)(iVar1 + 10) = 0;
      piVar2 = *(int **)(param_1 + 4);
      iVar3 = iVar3 + 1;
    } while (iVar3 <= piVar2[2]);
  }
  return;
}

