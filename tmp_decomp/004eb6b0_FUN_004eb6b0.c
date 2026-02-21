
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __fastcall FUN_004eb6b0(int param_1)

{
  int *piVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  char cVar5;
  int iVar6;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int *piVar8;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  uint uVar9;
  uint uVar10;
  float10 fVar11;
  float10 fVar12;
  int aiStack_18 [6];
  int iVar7;
  
  (**(code **)(**(int **)(param_1 + 0xb60) + 0x68))(&LAB_0040448a,param_1);
  aiStack_18[0] = 0;
  uVar10 = 3;
  aiStack_18[1] = 0;
  aiStack_18[2] = 0;
  aiStack_18[3] = 0;
  iVar6 = thunk_InitializeLinkedListCursorFromOwnerHead();
  bVar4 = thunk_LinkedListCursorHasCurrent();
  iVar7 = CONCAT31(extraout_var,bVar4);
  while (iVar7 != 0) {
    if ((*(char *)(iVar6 + 0x10) == '\0') && (*(char *)(iVar6 + 0x11) != 0)) {
      aiStack_18[*(char *)(iVar6 + 0x11)] = iVar6;
    }
    iVar6 = thunk_AdvanceLinkedListCursor();
    bVar4 = thunk_LinkedListCursorHasCurrent();
    iVar7 = CONCAT31(extraout_var_00,bVar4);
  }
  piVar8 = (int *)thunk_InitializeLinkedListCursorFromOwnerHead();
  bVar4 = thunk_LinkedListCursorHasCurrent();
  iVar6 = CONCAT31(extraout_var_01,bVar4);
  do {
    if (iVar6 == 0) {
      return;
    }
    uVar9 = (uint)*(char *)((int)piVar8 + 0x11);
    if ((int *)aiStack_18[uVar9] == piVar8) {
      aiStack_18[uVar9] = 0;
    }
    if (((uVar9 == 0) || ((uVar9 & uVar10) == uVar9)) || (bVar4 = false, (char)piVar8[2] == '\0')) {
      bVar4 = true;
    }
    if (bVar4) {
      if (((uVar9 & 1) != 0) && (cVar5 = (**(code **)(*piVar8 + 0x50))(), cVar5 == '\0')) {
        bVar4 = false;
      }
      if ((bVar4) && (uVar9 != 0)) {
        piVar1 = (int *)aiStack_18[uVar9];
        if (piVar1 != (int *)0x0) {
          fVar2 = (float)piVar1[3];
          fVar11 = (float10)(**(code **)(*piVar1 + 0x6c))();
          fVar3 = (float)piVar8[3];
          fVar12 = (float10)(**(code **)(*piVar8 + 0x6c))();
          if ((float10)fVar3 / fVar12 <
              (float10)(float)((float10)fVar2 / fVar11) * (float10)_DAT_006545f8) {
            bVar4 = false;
            goto LAB_004eb7fd;
          }
        }
        uVar10 = uVar10 & ~uVar9;
      }
    }
LAB_004eb7fd:
    (**(code **)(*piVar8 + 0x94))(!bVar4);
    piVar8 = (int *)thunk_AdvanceLinkedListCursor();
    bVar4 = thunk_LinkedListCursorHasCurrent();
    iVar6 = CONCAT31(extraout_var_02,bVar4);
  } while( true );
}

