
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

float10 __thiscall FUN_00537270(int *param_1,int param_2)

{
  float fVar1;
  float fVar2;
  code *pcVar3;
  float fVar4;
  short sVar5;
  int iVar6;
  undefined4 uVar7;
  int iVar8;
  undefined4 uVar9;
  uint uVar10;
  float *pfVar11;
  float *pfVar12;
  undefined4 *puVar13;
  float10 fVar14;
  float local_10 [4];
  
  if ((char)param_1[4] != '\0') {
    return (float10)_DAT_0065a9e8;
  }
  if (*(int **)(param_2 + 0x2c) != param_1) {
    puVar13 = (undefined4 *)param_1[9];
    local_10[0] = 0.0;
    local_10[1] = 0.0;
    local_10[2] = 0.0;
    local_10[3] = 0.0;
    if (puVar13 != (undefined4 *)0x0) {
      pcVar3 = *(code **)(*param_1 + 0xac);
      do {
        uVar9 = *puVar13;
        iVar6 = (*pcVar3)();
        if (iVar6 == 0) {
          sVar5 = 0;
        }
        else {
          uVar7 = (*pcVar3)();
          sVar5 = thunk_FUN_00550550(uVar7);
        }
        if (5 < sVar5) {
          sVar5 = 5;
        }
        thunk_FUN_00537c60(uVar9,local_10,*(undefined4 *)(&DAT_006978c8 + sVar5 * 4));
        puVar13 = (undefined4 *)puVar13[1];
      } while (puVar13 != (undefined4 *)0x0);
    }
    iVar6 = *param_1;
    pcVar3 = *(code **)(iVar6 + 0xac);
    iVar8 = (*pcVar3)();
    if (iVar8 == 0) {
      sVar5 = 0;
    }
    else {
      uVar9 = (*pcVar3)();
      sVar5 = thunk_FUN_00550550(uVar9);
    }
    if (5 < sVar5) {
      sVar5 = 5;
    }
    thunk_FUN_00537c60(param_2,local_10,*(undefined4 *)(&DAT_006978c8 + sVar5 * 4));
    pfVar12 = local_10;
    iVar8 = 4;
    pfVar11 = (float *)(param_1 + 0xb);
    fVar1 = _DAT_0065a9e8;
    fVar4 = _DAT_0065a9e8;
    do {
      fVar2 = *pfVar12;
      pfVar12 = pfVar12 + 1;
      iVar8 = iVar8 + -1;
      fVar4 = fVar4 + *pfVar11;
      fVar1 = fVar1 + SQRT(fVar2 * *pfVar11);
      pfVar11 = pfVar11 + 1;
    } while (iVar8 != 0);
    fVar14 = (float10)(**(code **)(iVar6 + 0x68))();
    return (float10)(fVar1 / fVar4) - fVar14;
  }
  puVar13 = (undefined4 *)param_1[9];
  local_10[0] = 0.0;
  local_10[1] = 0.0;
  local_10[2] = 0.0;
  local_10[3] = 0.0;
  if (puVar13 != (undefined4 *)0x0) {
    pcVar3 = *(code **)(*param_1 + 0xac);
    do {
      uVar9 = *puVar13;
      iVar6 = (*pcVar3)();
      if (iVar6 == 0) {
        sVar5 = 0;
      }
      else {
        uVar7 = (*pcVar3)();
        sVar5 = thunk_FUN_00550550(uVar7);
      }
      if (5 < sVar5) {
        sVar5 = 5;
      }
      thunk_FUN_00537c60(uVar9,local_10,*(undefined4 *)(&DAT_006978c8 + sVar5 * 4));
      puVar13 = (undefined4 *)puVar13[1];
    } while (puVar13 != (undefined4 *)0x0);
  }
  iVar6 = *param_1;
  pcVar3 = *(code **)(iVar6 + 0xac);
  iVar8 = (*pcVar3)();
  if (iVar8 == 0) {
    sVar5 = 0;
  }
  else {
    uVar9 = (*pcVar3)();
    sVar5 = thunk_FUN_00550550(uVar9);
  }
  if (5 < sVar5) {
    sVar5 = 5;
  }
  fVar1 = *(float *)(&DAT_006978c8 + sVar5 * 4);
  fVar2 = (float)_DAT_0065a9e0;
  sVar5 = thunk_GetNavyOrderNormalizationBaseByNationType();
  fVar4 = fVar1 * fVar2 * (float)((int)*(short *)(param_2 + 0x1c) / (int)sVar5);
  uVar10 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  local_10[0] = (float)(int)(short)uVar10 * fVar4 + local_10[0];
  uVar10 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  local_10[1] = (float)(int)(short)uVar10 * fVar4 + local_10[1];
  uVar10 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  local_10[2] = (float)(int)(short)uVar10 * fVar4 + local_10[2];
  uVar10 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  pfVar12 = local_10;
  iVar8 = 4;
  local_10[3] = (float)(int)(short)uVar10 * fVar1 * fVar2 + local_10[3];
  pfVar11 = (float *)(param_1 + 0xb);
  fVar1 = _DAT_0065a9e8;
  fVar4 = _DAT_0065a9e8;
  do {
    fVar2 = *pfVar12;
    pfVar12 = pfVar12 + 1;
    iVar8 = iVar8 + -1;
    fVar4 = fVar4 + *pfVar11;
    fVar1 = fVar1 + SQRT(*pfVar11 * fVar2);
    pfVar11 = pfVar11 + 1;
  } while (iVar8 != 0);
  fVar14 = (float10)(**(code **)(iVar6 + 0x68))();
  return fVar14 - (float10)fVar1 / (float10)fVar4;
}

