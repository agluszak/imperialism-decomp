
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined2 FUN_00536090(int *param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  float10 fVar3;
  float10 fVar4;
  
  iVar1 = *param_1;
  (**(code **)(iVar1 + 0xc))();
  iVar2 = *param_2;
  (**(code **)(iVar2 + 0xc))();
  fVar3 = (float10)(**(code **)(iVar1 + 0x68))();
  fVar3 = (float10)_DAT_0065a470 - fVar3;
  if ((float10)_DAT_0065a468 <= fVar3) {
    fVar3 = (float10)(float)param_1[3] * fVar3;
  }
  else {
    fVar3 = fVar3 / (float10)(float)param_1[3];
  }
  fVar4 = (float10)(**(code **)(iVar2 + 0x68))();
  fVar4 = (float10)_DAT_0065a470 - fVar4;
  if ((float10)_DAT_0065a468 <= fVar4) {
    fVar4 = fVar4 * (float10)(float)param_2[3];
  }
  else {
    fVar4 = fVar4 / (float10)(float)param_2[3];
  }
  if (fVar4 < (float10)(float)fVar3) {
    return 0xffff;
  }
  if ((float10)(float)fVar3 < fVar4) {
    return 1;
  }
  return 0;
}

