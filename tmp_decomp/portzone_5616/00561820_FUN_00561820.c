
void __thiscall FUN_00561820(int param_1,int *param_2)

{
  int iVar1;
  code *pcVar2;
  
  thunk_HandleCityDialogNoOpSlot14(param_2);
  iVar1 = *param_2;
  (**(code **)(iVar1 + 0xac))(param_1 + 8);
  pcVar2 = *(code **)(iVar1 + 0x78);
  (*pcVar2)(param_1 + 4,2);
  (*pcVar2)(param_1 + 0xc,4);
  (*pcVar2)(param_1 + 0x12,2);
  (*pcVar2)(param_1 + 0x20,2);
  (*pcVar2)(param_1 + 0x14,2);
  (*pcVar2)(param_1 + 0x48,2);
  return;
}

