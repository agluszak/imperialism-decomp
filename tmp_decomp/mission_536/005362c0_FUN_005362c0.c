
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

float10 FUN_005362c0(float *param_1,short *param_2,int param_3)

{
  float *pfVar1;
  int iVar2;
  float10 fVar3;
  float10 fVar4;
  float10 fVar5;
  
  fVar3 = (float10)_DAT_0065a9e8;
  pfVar1 = param_1;
  iVar2 = param_3;
  if (0 < param_3) {
    do {
      fVar3 = fVar3 + (float10)*pfVar1;
      iVar2 = iVar2 + -1;
      pfVar1 = pfVar1 + 1;
    } while (iVar2 != 0);
  }
  if (fVar3 != (float10)_DAT_0065a9f0) {
    fVar4 = (float10)_DAT_0065a9e8;
    if (0 < param_3) {
      do {
        fVar5 = (float10)*param_1 / fVar3 - (float10)(int)*param_2 * (float10)_DAT_0065a9f8;
        if (fVar5 <= (float10)_DAT_0065a9f0) {
          fVar5 = -fVar5;
        }
        fVar4 = fVar4 + fVar5;
        param_1 = param_1 + 1;
        param_2 = param_2 + 1;
        param_3 = param_3 + -1;
      } while (param_3 != 0);
    }
    return fVar3 * ((float10)_DAT_0065aa08 - fVar4 * (float10)_DAT_0065aa00);
  }
  return (float10)_DAT_0065a9e8;
}

