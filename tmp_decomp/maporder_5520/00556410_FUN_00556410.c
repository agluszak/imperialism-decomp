
void __fastcall FUN_00556410(int param_1)

{
  undefined2 uVar1;
  int extraout_ECX;
  int iVar2;
  undefined2 extraout_var;
  undefined2 extraout_var_00;
  undefined2 extraout_var_01;
  undefined4 uVar4;
  undefined2 uVar3;
  
  uVar4 = 0xffffffff;
  iVar2 = param_1;
  if (*(short *)(param_1 + 0x30) != -1) {
    thunk_FUN_00515e00(*(short *)(param_1 + 0x30),0xffffffff);
    *(undefined2 *)(param_1 + 0x30) = 0xffff;
    iVar2 = extraout_ECX;
  }
  uVar3 = (undefined2)((uint)iVar2 >> 0x10);
  switch(*(undefined4 *)(param_1 + 8)) {
  case 1:
    uVar4 = 4;
    goto LAB_00556473;
  default:
    goto switchD_0055643e_caseD_2;
  case 3:
    uVar4 = 5;
    uVar1 = (**(code **)(**(int **)(param_1 + 0x18) + 0x4c))();
    uVar3 = extraout_var;
    break;
  case 5:
    uVar4 = 6;
    uVar1 = (**(code **)(**(int **)(param_1 + 0x18) + 0x54))(*(undefined4 *)(param_1 + 0xc));
    uVar3 = extraout_var_00;
    break;
  case 6:
    uVar4 = 2;
LAB_00556473:
    uVar1 = (**(code **)(**(int **)(param_1 + 0xc) + 0x4c))();
    uVar3 = extraout_var_01;
  }
  *(undefined2 *)(param_1 + 0x30) = uVar1;
switchD_0055643e_caseD_2:
  if ((short)uVar4 != -1) {
    thunk_FUN_00515e00(CONCAT22(uVar3,*(undefined2 *)(param_1 + 0x30)),uVar4);
  }
  return;
}

