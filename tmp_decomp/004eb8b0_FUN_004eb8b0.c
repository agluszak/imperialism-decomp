
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __fastcall FUN_004eb8b0(int param_1)

{
  code *pcVar1;
  code *pcVar2;
  float fVar3;
  bool bVar4;
  int *piVar5;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int *piVar7;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  int iVar8;
  int iVar9;
  void *pvVar10;
  int *piVar11;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  undefined3 extraout_var_05;
  undefined3 extraout_var_06;
  int iVar12;
  void *pvVar13;
  int *piVar14;
  float10 fVar15;
  float10 fVar16;
  float fVar17;
  float fStack_78;
  int local_70;
  int aiStack_50 [9];
  float afStack_2c [11];
  int iVar6;
  
  piVar5 = (int *)thunk_InitializeLinkedListCursorFromOwnerHead();
  bVar4 = thunk_LinkedListCursorHasCurrent();
  iVar6 = CONCAT31(extraout_var,bVar4);
  while (iVar6 != 0) {
    (**(code **)(*piVar5 + 0x98))();
    piVar5 = (int *)thunk_AdvanceLinkedListCursor();
    bVar4 = thunk_LinkedListCursorHasCurrent();
    iVar6 = CONCAT31(extraout_var_00,bVar4);
  }
  do {
    piVar5 = (int *)0x0;
    piVar7 = (int *)thunk_InitializeLinkedListCursorFromOwnerHead();
    bVar4 = thunk_LinkedListCursorHasCurrent();
    iVar6 = CONCAT31(extraout_var_01,bVar4);
    while (iVar6 != 0) {
      piVar7 = (int *)(**(code **)(*piVar7 + 0x5c))();
      if ((piVar7 == (int *)0x0) || ((char)piVar7[4] != '\0')) goto LAB_004eba38;
      if (piVar5 == (int *)0x0) {
LAB_004eba36:
        piVar5 = piVar7;
      }
      else {
        pcVar1 = *(code **)(*piVar7 + 0x68);
        fVar15 = (float10)(*pcVar1)();
        fVar15 = (float10)_DAT_006545d8 - fVar15;
        if ((float10)_DAT_006545d0 <= fVar15) {
          fVar15 = (float10)(float)piVar7[3] * fVar15;
        }
        else {
          fVar15 = fVar15 / (float10)(float)piVar7[3];
        }
        pcVar2 = *(code **)(*piVar5 + 0x68);
        fVar16 = (float10)(*pcVar2)();
        fVar16 = (float10)_DAT_006545d8 - fVar16;
        if ((float10)_DAT_006545d0 <= fVar16) {
          fVar16 = fVar16 * (float10)(float)piVar5[3];
        }
        else {
          fVar16 = fVar16 / (float10)(float)piVar5[3];
        }
        if (((float)_DAT_006545f0 < (float)fVar15) && ((char)piVar7[2] < (char)piVar5[2]))
        goto LAB_004eba36;
        if ((fVar16 <= (float10)_DAT_006545f0) || ((char)piVar7[2] <= (char)piVar5[2])) {
          fVar15 = (float10)(*pcVar2)();
          fVar15 = (float10)_DAT_006545d8 - fVar15;
          if ((float10)_DAT_006545d0 <= fVar15) {
            fVar15 = (float10)(float)piVar5[3] * fVar15;
          }
          else {
            fVar15 = fVar15 / (float10)(float)piVar5[3];
          }
          fVar16 = (float10)(*pcVar1)();
          fVar16 = (float10)_DAT_006545d8 - fVar16;
          if ((float10)_DAT_006545d0 <= fVar16) {
            fVar16 = fVar16 * (float10)(float)piVar7[3];
          }
          else {
            fVar16 = fVar16 / (float10)(float)piVar7[3];
          }
          if ((float10)(float)fVar15 < fVar16) goto LAB_004eba36;
        }
      }
LAB_004eba38:
      piVar7 = (int *)thunk_AdvanceLinkedListCursor();
      bVar4 = thunk_LinkedListCursorHasCurrent();
      iVar6 = CONCAT31(extraout_var_02,bVar4);
    }
    if (piVar5 == (int *)0x0) {
LAB_004ebaff:
      while( true ) {
        piVar7 = (int *)0x0;
        piVar11 = (int *)thunk_InitializeLinkedListCursorFromOwnerHead();
        bVar4 = thunk_LinkedListCursorHasCurrent();
        iVar6 = CONCAT31(extraout_var_03,bVar4);
        piVar5 = (int *)0x0;
        while (iVar6 != 0) {
          piVar11 = (int *)(**(code **)(*piVar11 + 0x58))();
          piVar14 = piVar5;
          if ((piVar11 != (int *)0x0) && ((char)piVar11[4] == '\0')) {
            fVar15 = (float10)(**(code **)(*piVar11 + 0x68))();
            fVar15 = (float10)_DAT_006545d8 - fVar15;
            if ((float10)_DAT_006545d0 <= fVar15) {
              fVar15 = (float10)(float)piVar11[3] * fVar15;
            }
            else {
              fVar15 = fVar15 / (float10)(float)piVar11[3];
            }
            fVar17 = (float)fVar15;
            if (((piVar7 == (int *)0x0) && ((float)_DAT_006545f0 < fVar17)) &&
               ((*(byte *)((int)piVar11 + 0x11) & 1) != 0)) {
              piVar7 = piVar11;
            }
            piVar14 = piVar11;
            if (piVar5 != (int *)0x0) {
              fVar15 = (float10)(**(code **)(*piVar5 + 0x68))();
              fVar15 = (float10)_DAT_006545d8 - fVar15;
              if ((float10)_DAT_006545d0 <= fVar15) {
                fVar15 = fVar15 * (float10)(float)piVar5[3];
              }
              else {
                fVar15 = fVar15 / (float10)(float)piVar5[3];
              }
              if ((((fVar17 <= (float)_DAT_006545f0) || ((char)piVar5[2] <= (char)piVar11[2])) &&
                  ((fVar15 <= (float10)_DAT_006545f0 ||
                   (piVar14 = piVar5, (char)piVar11[2] <= (char)piVar5[2])))) &&
                 (piVar14 = piVar5, fVar15 < (float10)fVar17)) {
                piVar14 = piVar11;
              }
            }
          }
          piVar11 = (int *)thunk_AdvanceLinkedListCursor();
          bVar4 = thunk_LinkedListCursorHasCurrent();
          piVar5 = piVar14;
          iVar6 = CONCAT31(extraout_var_04,bVar4);
        }
        if (piVar5 == (int *)0x0) break;
        if (((piVar7 != (int *)0x0) && ((char)piVar7[2] <= (char)piVar5[2])) &&
           ((*(byte *)((int)piVar5 + 0x11) & 1) == 0)) {
          fVar17 = (float)piVar5[3];
          fVar15 = (float10)(**(code **)(*piVar5 + 0x6c))();
          fVar3 = (float)piVar7[3];
          fVar16 = (float10)(**(code **)(*piVar7 + 0x6c))();
          if ((float)((float10)fVar17 / fVar15) < (float)((float10)fVar3 / fVar16)) {
            piVar5 = piVar7;
          }
        }
        iVar6 = *piVar5;
        piVar5 = aiStack_50 + 2;
        for (iVar12 = 9; iVar12 != 0; iVar12 = iVar12 + -1) {
          *piVar5 = 0;
          piVar5 = piVar5 + 1;
        }
        (**(code **)(iVar6 + 0x2c))(aiStack_50 + 2,0);
        local_70 = 0;
        piVar5 = aiStack_50;
        iVar12 = 9;
        do {
          if (*piVar5 < 0) {
            *piVar5 = 0;
          }
          iVar8 = *piVar5;
          piVar5 = piVar5 + 1;
          local_70 = local_70 + iVar8;
          iVar12 = iVar12 + -1;
        } while (iVar12 != 0);
        if (local_70 == 0) {
          local_70 = 1;
        }
        iVar12 = 0;
        do {
          iVar8 = iVar12 + 4;
          *(float *)((int)afStack_2c + iVar12) =
               (float)*(int *)((int)aiStack_50 + iVar12) / (float)local_70;
          iVar12 = iVar8;
        } while (iVar8 < 0x24);
        iVar12 = 0;
        fVar17 = 0.0;
        iVar8 = thunk_InitializeLinkedListCursorFromOwnerHead();
        bVar4 = thunk_LinkedListCursorHasCurrent();
        iVar9 = CONCAT31(extraout_var_05,bVar4);
        while (iVar9 != 0) {
          if ((*(int *)(iVar8 + 0x40) == 0) &&
             ((fVar15 = (float10)(**(code **)(iVar6 + 0x78))(iVar8,afStack_2c), iVar12 == 0 ||
              ((float10)fVar17 < fVar15)))) {
            fVar17 = (float)fVar15;
            iVar12 = iVar8;
          }
          iVar8 = thunk_AdvanceLinkedListCursor();
          bVar4 = thunk_LinkedListCursorHasCurrent();
          iVar9 = CONCAT31(extraout_var_06,bVar4);
        }
        if (iVar12 == 0) {
          return;
        }
        (**(code **)(iVar6 + 0x80))(iVar12,1);
      }
      return;
    }
    iVar6 = *piVar5;
    piVar5 = aiStack_50 + 2;
    for (iVar12 = 9; iVar12 != 0; iVar12 = iVar12 + -1) {
      *piVar5 = 0;
      piVar5 = piVar5 + 1;
    }
    iVar8 = (**(code **)(iVar6 + 0x2c))(aiStack_50 + 2,0);
    iVar12 = 0;
    do {
      iVar9 = iVar12 + 4;
      *(float *)((int)afStack_2c + iVar12 + 8) =
           (float)*(int *)((int)aiStack_50 + iVar12 + 8) / (float)iVar8;
      iVar12 = iVar9;
    } while (iVar9 < 0x24);
    pvVar13 = (void *)0x0;
    fStack_78 = 0.0;
    for (pvVar10 = thunk_GetNavyPrimaryOrderListHead(); pvVar10 != (void *)0x0;
        pvVar10 = *(void **)((int)pvVar10 + 0x24)) {
      if (((*(short *)((int)pvVar10 + 0x14) == *(short *)(param_1 + 0xc)) &&
          (*(int *)((int)pvVar10 + 0x2c) == 0)) &&
         ((fVar15 = (float10)(**(code **)(iVar6 + 0x7c))(pvVar10,afStack_2c + 2),
          pvVar13 == (void *)0x0 || ((float10)fStack_78 < fVar15)))) {
        fStack_78 = (float)fVar15;
        pvVar13 = pvVar10;
      }
    }
    if (pvVar13 == (void *)0x0) goto LAB_004ebaff;
    (**(code **)(iVar6 + 0x84))(pvVar13,1);
  } while( true );
}

