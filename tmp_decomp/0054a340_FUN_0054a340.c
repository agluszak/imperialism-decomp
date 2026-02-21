
void FUN_0054a340(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 local_20;
  undefined4 local_1c;
  int local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined1 local_c;
  undefined4 local_8;
  undefined4 local_4;
  
  local_10 = 0x74696d65;
  local_c = thunk_GetActiveNationId();
  local_20 = 0x1f;
  local_1c = 0;
  local_14 = 0x20;
  if ((param_3 == -2) || (param_3 == -3)) {
    local_18 = 0;
  }
  else if (param_3 == -1) {
    local_18 = param_3;
  }
  else {
    local_18 = *(int *)(g_pGameFlowState + 0x48 + param_3 * 4);
  }
  local_8 = param_1;
  local_4 = param_2;
  thunk_FUN_005e3d40(&local_20,param_3 == -3);
  return;
}

