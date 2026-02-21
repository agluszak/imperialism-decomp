
void __thiscall FUN_0055fb60(int *param_1,undefined4 param_2,short param_3)

{
  char cVar1;
  undefined4 uVar2;
  undefined2 extraout_var;
  undefined2 extraout_var_00;
  undefined2 extraout_var_01;
  
  *(short *)((int)param_1 + 0x12) = (short)param_2;
  if (param_3 == -1) {
    param_3 = thunk_FUN_005178f0(param_2,0);
  }
  param_1[3] = (int)param_3;
  *(short *)(param_1 + 8) = (short)param_1[3];
  cVar1 = (**(code **)(*param_1 + 0x38))();
  if (cVar1 != '\0') {
    thunk_FUN_00515e00((short)param_1[8],0xfffffff2);
    return;
  }
  thunk_FUN_00515e00(CONCAT22(extraout_var_00,(short)param_1[8]),0xfffffff0);
  uVar2 = thunk_StepHexTileIndexByDirectionWithWrapRules
                    (CONCAT22(extraout_var_01,(short)param_1[8]),5);
  thunk_FUN_00515e00(uVar2,0xffffffee);
  uVar2 = thunk_StepHexTileIndexByDirectionWithWrapRules(CONCAT22(extraout_var,(short)param_1[8]),0)
  ;
  thunk_FUN_00515e00(uVar2,0xffffffec);
  return;
}

