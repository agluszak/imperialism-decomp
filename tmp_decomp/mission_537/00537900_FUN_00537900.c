
void __thiscall FUN_00537900(int param_1,float *param_2,int param_3,short param_4,int param_5)

{
  int *piVar1;
  int iVar2;
  float fVar3;
  short sVar4;
  short sVar5;
  uint uVar6;
  
  sVar4 = param_4;
  *param_2 = 0.0;
  param_2[1] = 0.0;
  param_2[2] = 0.0;
  param_2[3] = 0.0;
  if (param_5 == param_3) {
    param_5 = 0;
  }
  piVar1 = *(int **)(param_1 + 0x24);
  do {
    if (piVar1 == (int *)0x0) {
      return;
    }
    if ((param_3 == 0) || (sVar5 = thunk_FUN_00550550(param_3), sVar5 <= sVar4)) {
      iVar2 = *piVar1;
      sVar5 = thunk_GetNavyOrderNormalizationBaseByNationType();
      fVar3 = (float)((int)*(short *)(iVar2 + 0x1c) / (int)sVar5);
      uVar6 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      *param_2 = (float)(int)(short)uVar6 * fVar3 + *param_2;
      uVar6 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      param_2[1] = (float)(int)(short)uVar6 * fVar3 + param_2[1];
      uVar6 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      param_2[2] = (float)(int)(short)uVar6 * fVar3 + param_2[2];
      uVar6 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      sVar5 = (short)uVar6;
LAB_00537a90:
      _param_4 = (int)sVar5;
      param_2[3] = (float)_param_4 + param_2[3];
    }
    else if ((param_5 != 0) && (sVar5 = thunk_FUN_00550550(param_5), sVar5 <= sVar4)) {
      iVar2 = *piVar1;
      sVar5 = thunk_GetNavyOrderNormalizationBaseByNationType();
      fVar3 = (float)((int)*(short *)(iVar2 + 0x1c) / (int)sVar5);
      uVar6 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      *param_2 = (float)(int)(short)uVar6 * fVar3 + *param_2;
      uVar6 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      param_2[1] = (float)(int)(short)uVar6 * fVar3 + param_2[1];
      uVar6 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      param_2[2] = (float)(int)(short)uVar6 * fVar3 + param_2[2];
      uVar6 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      sVar5 = (short)uVar6;
      goto LAB_00537a90;
    }
    piVar1 = (int *)piVar1[1];
  } while( true );
}

