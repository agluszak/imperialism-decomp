
uint __fastcall FUN_00536fc0(int *param_1)

{
  char cVar1;
  int iVar2;
  
  if ((int *)param_1[6] != (int *)0x0) {
    cVar1 = (**(code **)(*(int *)param_1[6] + 0x38))();
    if (cVar1 != '\0') {
      cVar1 = (**(code **)(*(int *)param_1[6] + 0x40))((short)param_1[1]);
      if (cVar1 == '\0') {
        iVar2 = (**(code **)(*param_1 + 0xa0))();
        param_1[6] = iVar2;
      }
    }
  }
  return -(uint)(param_1[6] != 0) & (uint)param_1;
}

