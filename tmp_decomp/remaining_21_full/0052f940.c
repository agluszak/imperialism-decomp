// 0x0052f940 FUN_0052f940\n\n
void __fastcall FUN_0052f940(int *param_1)

{
  int iVar1;
  char cVar2;
  undefined2 extraout_var;
  
  iVar1 = *param_1;
  (**(code **)(iVar1 + 0x48))();
  if ((short)param_1[6] < *(short *)((int)param_1 + 0x1a)) {
    cVar2 = (**(code **)(iVar1 + 0x88))();
    if (cVar2 == '\0') goto LAB_0052f978;
  }
  (**(code **)(**(int **)(param_1[1] + 0x98) + 0x68))((short)param_1[7]);
  *(undefined2 *)(param_1 + 6) = 0;
LAB_0052f978:
  (**(code **)(iVar1 + 0x84))();
  if ((short)param_1[4] != -10) {
    (**(code **)(*(int *)param_1[1] + 0x1a4))(CONCAT22(extraout_var,(short)param_1[4]),0xffffffff);
    *(undefined2 *)((int)param_1 + (short)param_1[4] * 2 + 0x1e) =
         *(undefined2 *)((int)param_1 + 0x12);
  }
  return;
}

