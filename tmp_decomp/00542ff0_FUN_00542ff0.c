
void __thiscall FUN_00542ff0(int param_1,int *param_2)

{
  int iVar1;
  code *pcVar2;
  code *pcVar3;
  int *piVar4;
  int iVar5;
  
  piVar4 = param_2;
  thunk_HandleCityDialogNoOpSlot14(param_2);
  iVar1 = *param_2;
  iVar5 = param_1 + 0x78;
  param_2 = (int *)0x7;
  pcVar2 = *(code **)(iVar1 + 0x78);
  pcVar3 = *(code **)(iVar1 + 0xac);
  do {
    (*pcVar2)(iVar5 + -0x30,4);
    (*pcVar3)(iVar5);
    (*pcVar3)(iVar5 + 0x1c);
    iVar5 = iVar5 + 4;
    param_2 = (int *)((int)param_2 + -1);
  } while (param_2 != (int *)0x0);
  (*pcVar3)(param_1 + 0xb0);
  (*pcVar3)(param_1 + 0x74);
  (*pcVar2)(param_1 + 100,4);
  (*pcVar2)(param_1 + 0xe4,1);
  (**(code **)(*DAT_006a6014 + 0x14))(piVar4);
  return;
}

