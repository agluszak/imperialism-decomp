// 0x0052e840 FUN_0052e840\n\n
undefined4 __fastcall FUN_0052e840(int *param_1)

{
  int iVar1;
  undefined1 uVar2;
  
  uVar2 = 0;
  (**(code **)(*param_1 + 0x70))(0);
  param_1 = param_1 + 4;
  iVar1 = 0x195;
  do {
    if ((char)*param_1 == -1) {
      *(char *)param_1 = 'd';
      uVar2 = 1;
    }
    else if ((char)*param_1 == -9) {
      *(char *)param_1 = -1;
    }
    param_1 = (int *)((int)param_1 + 1);
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  return CONCAT31((int3)((uint)param_1 >> 8),uVar2);
}

