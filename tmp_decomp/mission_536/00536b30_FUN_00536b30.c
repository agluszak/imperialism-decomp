
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __fastcall FUN_00536b30(int *param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined2 extraout_var;
  int iVar4;
  float *pfVar5;
  float *pfVar6;
  int iVar7;
  float afStack_10 [4];
  
  iVar4 = *param_1;
  (**(code **)(iVar4 + 0x34))();
  (**(code **)(iVar4 + 0x38))();
  (**(code **)(iVar4 + 0x3c))();
  thunk_FUN_0055f540(CONCAT22(extraout_var,(short)param_1[1]));
  if (param_1[9] == 0) {
    param_1[10] = 0;
    return;
  }
  iVar7 = param_1[10];
  if (iVar7 == 0) {
    thunk_BuildNavyOrderCategoryVectorForNationWithExclusion(afStack_10,param_1[5],1,param_1[6]);
    fVar2 = 0.0;
    fVar3 = 0.0;
    pfVar6 = afStack_10;
    iVar4 = 4;
    pfVar5 = (float *)(param_1 + 0xb);
    do {
      fVar1 = *pfVar6;
      pfVar6 = pfVar6 + 1;
      iVar4 = iVar4 + -1;
      fVar3 = fVar3 + *pfVar5;
      fVar2 = fVar2 + SQRT(*pfVar5 * fVar1);
      pfVar5 = pfVar5 + 1;
    } while (iVar4 != 0);
    if (_DAT_0065a8f0 <= fVar2 / fVar3) {
      thunk_BuildNavyOrderCategoryVectorForNationWithExclusion(afStack_10,param_1[5],0,param_1[6]);
      fVar2 = 0.0;
      fVar3 = 0.0;
      pfVar6 = afStack_10;
      iVar4 = 4;
      pfVar5 = (float *)(param_1 + 0xb);
      do {
        fVar1 = *pfVar6;
        pfVar6 = pfVar6 + 1;
        iVar4 = iVar4 + -1;
        fVar3 = fVar3 + *pfVar5;
        fVar2 = fVar2 + SQRT(fVar1 * *pfVar5);
        pfVar5 = pfVar5 + 1;
      } while (iVar4 != 0);
      if (_DAT_0065a8f0 <= fVar2 / fVar3) goto LAB_00536cd3;
      param_1[10] = 1;
    }
  }
  else {
    if (iVar7 == 1) {
LAB_00536cd3:
      param_1[10] = 2;
      return;
    }
    if (iVar7 == 2) {
      thunk_BuildNavyOrderCategoryVectorForNationWithExclusion(afStack_10,param_1[5],1,param_1[6]);
      fVar2 = 0.0;
      fVar3 = 0.0;
      pfVar6 = afStack_10;
      iVar7 = 4;
      pfVar5 = (float *)(param_1 + 0xb);
      do {
        fVar1 = *pfVar6;
        pfVar6 = pfVar6 + 1;
        iVar7 = iVar7 + -1;
        fVar3 = fVar3 + *pfVar5;
        fVar2 = fVar2 + SQRT(fVar1 * *pfVar5);
        pfVar5 = pfVar5 + 1;
      } while (iVar7 != 0);
      if (fVar2 / fVar3 < _DAT_0065a8f4) {
        param_1[10] = 0;
        iVar4 = (**(code **)(iVar4 + 0xa0))();
        param_1[6] = iVar4;
        return;
      }
    }
  }
  return;
}

