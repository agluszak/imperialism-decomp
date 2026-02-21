
float10 __thiscall FUN_00537eb0(int param_1,undefined4 param_2)

{
  float fVar1;
  float *pfVar2;
  float *pfVar3;
  int iVar4;
  float10 fVar5;
  float10 fVar6;
  float local_10 [4];
  
  thunk_FUN_00537900(local_10,*(undefined4 *)(param_1 + 0x14),param_2,
                     *(undefined4 *)(param_1 + 0x18));
  fVar5 = (float10)0.0;
  fVar6 = (float10)0.0;
  pfVar3 = local_10;
  iVar4 = 4;
  pfVar2 = (float *)(param_1 + 0x2c);
  do {
    fVar1 = *pfVar3;
    pfVar3 = pfVar3 + 1;
    iVar4 = iVar4 + -1;
    fVar6 = fVar6 + (float10)*pfVar2;
    fVar5 = fVar5 + SQRT((float10)*pfVar2 * (float10)fVar1);
    pfVar2 = pfVar2 + 1;
  } while (iVar4 != 0);
  return fVar5 / fVar6;
}

