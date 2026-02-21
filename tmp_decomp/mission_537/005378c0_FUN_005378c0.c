
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

float10 __fastcall FUN_005378c0(int param_1)

{
  float fVar1;
  float fVar2;
  float *pfVar3;
  float *pfVar4;
  float10 fVar5;
  
  fVar5 = (float10)_DAT_0065a9e8;
  pfVar3 = (float *)&DAT_0065a910;
  pfVar4 = (float *)(param_1 + 0x2c);
  do {
    fVar1 = *pfVar4;
    fVar2 = *pfVar3;
    pfVar3 = pfVar3 + 1;
    pfVar4 = pfVar4 + 1;
    fVar5 = (float10)fVar1 * (float10)fVar2 + fVar5;
  } while ((int)pfVar3 < 0x65a920);
  return fVar5;
}

