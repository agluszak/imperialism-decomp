
void __thiscall FUN_0055cda0(int param_1,int param_2,int param_3,int param_4)

{
  bool bVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int local_10;
  int local_c;
  int local_8;
  
  iVar2 = param_3;
  bVar1 = 6 < param_3;
  param_3._0_1_ = 6 < param_4;
  if ((((6 < param_2) && (param_2 < 0xe)) || (param_2 == 0x12)) || (param_2 == 0x14)) {
    param_3._0_1_ = true;
  }
  iVar4 = 1;
  while( true ) {
    if (((bVar1) && (param_3._0_1_)) || ((*(int **)(param_1 + 0xef0))[2] < iVar4)) break;
    piVar3 = (int *)(**(code **)(**(int **)(param_1 + 0xef0) + 0x2c))(iVar4);
    if (*piVar3 == param_2) {
      if ((!bVar1) && (piVar3[1] == iVar2)) {
        bVar1 = true;
        piVar3[2] = piVar3[2] | 1 << ((byte)param_4 & 0x1f);
      }
      if ((!param_3._0_1_) && (piVar3[1] == param_4)) {
        param_3._0_1_ = true;
        piVar3[2] = piVar3[2] | 1 << ((byte)iVar2 & 0x1f);
      }
    }
    iVar4 = iVar4 + 1;
  }
  if (!bVar1) {
    local_10 = param_2;
    local_8 = 1 << ((byte)param_4 & 0x1f);
    local_c = iVar2;
    (**(code **)(**(int **)(param_1 + 0xef0) + 0x38))(&local_10);
  }
  if (!param_3._0_1_) {
    local_10 = param_2;
    local_8 = 1 << ((byte)iVar2 & 0x1f);
    local_c = param_4;
    (**(code **)(**(int **)(param_1 + 0xef0) + 0x38))(&local_10);
  }
  return;
}

