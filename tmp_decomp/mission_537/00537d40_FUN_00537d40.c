
void __thiscall FUN_00537d40(int *param_1,float *param_2)

{
  float fVar1;
  code *pcVar2;
  int iVar3;
  float fVar4;
  short sVar5;
  int iVar6;
  undefined4 uVar7;
  uint uVar8;
  int *piVar9;
  
  *param_2 = 0.0;
  param_2[1] = 0.0;
  param_2[2] = 0.0;
  param_2[3] = 0.0;
  piVar9 = (int *)param_1[9];
  if (piVar9 != (int *)0x0) {
    pcVar2 = *(code **)(*param_1 + 0xac);
    do {
      iVar3 = *piVar9;
      iVar6 = (*pcVar2)();
      if (iVar6 == 0) {
        sVar5 = 0;
      }
      else {
        uVar7 = (*pcVar2)();
        sVar5 = thunk_FUN_00550550(uVar7);
      }
      if (5 < sVar5) {
        sVar5 = 5;
      }
      fVar1 = *(float *)(&DAT_006978c8 + sVar5 * 4);
      sVar5 = thunk_GetNavyOrderNormalizationBaseByNationType();
      fVar4 = fVar1 * (float)((int)*(short *)(iVar3 + 0x1c) / (int)sVar5);
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      *param_2 = (float)(int)(short)uVar8 * fVar4 + *param_2;
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      param_2[1] = (float)(int)(short)uVar8 * fVar4 + param_2[1];
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      param_2[2] = (float)(int)(short)uVar8 * fVar4 + param_2[2];
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      param_2[3] = (float)(int)(short)uVar8 * fVar1 + param_2[3];
      piVar9 = (int *)piVar9[1];
    } while (piVar9 != (int *)0x0);
  }
  return;
}

