
void __thiscall FUN_00560580(int *param_1,char param_2)

{
  int *piVar1;
  code *pcVar2;
  char cVar3;
  undefined4 uVar4;
  undefined2 uVar5;
  undefined2 extraout_var;
  undefined2 extraout_var_00;
  undefined2 extraout_var_01;
  undefined2 extraout_var_02;
  undefined2 extraout_var_03;
  undefined4 unaff_EDI;
  int iVar6;
  
  piVar1 = *(int **)(g_pUiRuntimeContext + 0xf0);
  if (((bool)param_2 !=
       -1 < *(char *)(*(int *)(g_pGlobalMapState + 0xc) + 0x16 + (short)param_1[8] * 0x24)) &&
     (piVar1 != (int *)0x0)) {
    cVar3 = (-(param_2 != '\0') & 2U) - 1;
    uVar4 = (**(code **)(*param_1 + 0x38))();
    uVar5 = (undefined2)((uint)uVar4 >> 0x10);
    if ((char)uVar4 != '\0') {
      thunk_FUN_00515e00(CONCAT22(extraout_var_02,(short)param_1[8]),
                         CONCAT22(uVar5,(short)cVar3) * 0xe);
      (**(code **)(*piVar1 + 0x1d8))(CONCAT22(extraout_var_01,(short)param_1[8]));
      return;
    }
    iVar6 = CONCAT22((short)((uint)unaff_EDI >> 0x10),(short)cVar3);
    thunk_FUN_00515e00(CONCAT22(uVar5,(short)param_1[8]),iVar6 << 4);
    pcVar2 = *(code **)(*piVar1 + 0x1d8);
    (*pcVar2)(CONCAT22(extraout_var_03,(short)param_1[8]));
    uVar4 = thunk_StepHexTileIndexByDirectionWithWrapRules
                      (CONCAT22(extraout_var,(short)param_1[8]),5);
    thunk_FUN_00515e00(uVar4,iVar6 * 0x12);
    (*pcVar2)(uVar4);
    uVar4 = thunk_StepHexTileIndexByDirectionWithWrapRules
                      (CONCAT22(extraout_var_00,(short)param_1[8]),0);
    thunk_FUN_00515e00(uVar4,iVar6 * 0x14);
    (*pcVar2)(uVar4);
  }
  return;
}

