
void FUN_00537c60(int param_1,float *param_2,float param_3)

{
  float fVar1;
  short sVar2;
  uint uVar3;
  
  sVar2 = thunk_GetNavyOrderNormalizationBaseByNationType();
  fVar1 = (float)((int)*(short *)(param_1 + 0x1c) / (int)sVar2) * param_3;
  uVar3 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  *param_2 = (float)(int)(short)uVar3 * fVar1 + *param_2;
  uVar3 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  param_2[1] = (float)(int)(short)uVar3 * fVar1 + param_2[1];
  uVar3 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  param_2[2] = (float)(int)(short)uVar3 * fVar1 + param_2[2];
  uVar3 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  param_2[3] = (float)(int)(short)uVar3 * param_3 + param_2[3];
  return;
}

