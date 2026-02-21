
void __fastcall MissionCommon_VtblSlot1C(int *param_1)

{
  int *piVar1;
  
  if ((int *)param_1[8] != (int *)0x0) {
    (**(code **)(*(int *)param_1[8] + 0x1c))();
  }
  piVar1 = (int *)param_1[9];
  param_1[8] = 0;
  while (piVar1 != (int *)0x0) {
    *(undefined4 *)(*(int *)param_1[9] + 0x2c) = 0;
    piVar1 = thunk_DeleteMapOrderChildLinkAndReturnNext((int *)param_1[9]);
    param_1[9] = (int)piVar1;
  }
  if (param_1 != (int *)0x0) {
    (**(code **)(*param_1 + 4))(1);
  }
  return;
}

