
short FUN_00535f80(int *param_1,int *param_2,int param_3)

{
  int iVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  short sVar5;
  short sVar6;
  float10 fVar7;
  float10 fVar8;
  
  iVar1 = *param_1;
  (**(code **)(iVar1 + 0xc))();
  iVar2 = *param_2;
  (**(code **)(iVar2 + 0xc))();
  sVar6 = (-(ushort)(param_3 != 0) & 2) - 1;
  sVar5 = (-(ushort)(param_3 != 0) & 0xfffe) + 1;
  if ((char)param_2[2] < (char)param_1[2]) {
    return sVar6;
  }
  if ((char)param_1[2] < (char)param_2[2]) {
    return sVar5;
  }
  fVar3 = (float)param_1[3];
  fVar7 = (float10)(**(code **)(iVar1 + 0x6c))();
  fVar4 = (float)param_2[3];
  fVar8 = (float10)(**(code **)(iVar2 + 0x6c))();
  if ((float)((float10)fVar3 / fVar7) < (float)((float10)fVar4 / fVar8)) {
    return sVar6;
  }
  if ((float)((float10)fVar4 / fVar8) < (float)((float10)fVar3 / fVar7)) {
    return sVar5;
  }
  return 0;
}

