// 0x0052e350 FUN_0052e350\n\n
void __fastcall FUN_0052e350(int param_1)

{
  int iVar1;
  undefined2 *puVar2;
  undefined4 *puVar3;
  short *psVar4;
  undefined2 extraout_var;
  int iVar5;
  undefined4 uVar6;
  undefined2 uVar8;
  undefined2 extraout_var_00;
  uint uVar7;
  undefined2 extraout_var_01;
  short sVar9;
  int iVar10;
  int iVar11;
  uint uVar12;
  bool bVar13;
  int local_18;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  undefined4 local_4;
  
  iVar10 = 0;
  uVar12 = 0;
  local_18 = 0;
  if (DAT_006a390c != 0) {
    uVar7 = DAT_006a390c;
    iVar11 = DAT_006a3904;
    if (DAT_006a390c == 0) {
      iVar5 = 0;
      goto LAB_0052e386;
    }
    do {
      iVar5 = iVar11 + iVar10;
LAB_0052e386:
      if (uVar12 < uVar7) {
        iVar1 = iVar11 + iVar10;
      }
      else {
        iVar1 = 0;
      }
      if (*(short *)(iVar5 + 0x10) == *(short *)(iVar1 + 0x12)) {
        if (uVar12 < uVar7) {
          puVar2 = (undefined2 *)(iVar11 + iVar10);
        }
        else {
          puVar2 = (undefined2 *)0x0;
        }
        puVar2[9] = 0xffff;
        puVar2[3] = 0;
        puVar2[1] = 0;
        puVar2[2] = 0;
        *puVar2 = 0;
        puVar2[8] = 0xffff;
        *(undefined4 *)(puVar2 + 6) = 0xffffffff;
        *(undefined4 *)(puVar2 + 4) = 0xffffffff;
        uVar7 = DAT_006a390c;
        iVar11 = DAT_006a3904;
      }
      if (uVar12 < uVar7) {
        psVar4 = (short *)(iVar11 + iVar10);
      }
      else {
        psVar4 = (short *)0x0;
      }
      if ((*psVar4 == psVar4[2]) && (psVar4[1] == psVar4[3])) {
        bVar13 = true;
      }
      else {
        bVar13 = false;
      }
      if (!bVar13) {
        local_18 = local_18 + 1;
      }
      uVar12 = uVar12 + 1;
      iVar10 = iVar10 + 0x18;
    } while (uVar12 < uVar7);
  }
  thunk_FUN_0052e7b0(local_18);
  sVar9 = 0;
  uVar12 = 0;
  uVar8 = extraout_var;
  if (DAT_006a390c != 0) {
    iVar11 = 0;
    iVar10 = DAT_006a3904;
    uVar7 = DAT_006a390c;
    if (DAT_006a390c == 0) {
      psVar4 = (short *)0x0;
      goto LAB_0052e443;
    }
    do {
      psVar4 = (short *)(iVar10 + iVar11);
LAB_0052e443:
      if ((*psVar4 == psVar4[2]) && (psVar4[1] == psVar4[3])) {
        bVar13 = true;
      }
      else {
        bVar13 = false;
      }
      if (!bVar13) {
        if (uVar12 < uVar7) {
          iVar5 = iVar10 + iVar11;
        }
        else {
          iVar5 = 0;
        }
        if (*(short *)(iVar5 + 0x10) != -1) {
          if (uVar12 < uVar7) {
            iVar5 = iVar10 + iVar11;
          }
          else {
            iVar5 = 0;
          }
          if (*(short *)(iVar5 + 0x12) != -1) goto LAB_0052e4af;
        }
        if (DAT_006a3914 == 0) {
          thunk_TemporarilyClearAndRestoreUiInvalidationFlag
                    (s_D__Ambit_Cross_UMapper_cpp_006976e4,0x128f);
          iVar10 = DAT_006a3904;
          uVar7 = DAT_006a390c;
        }
      }
LAB_0052e4af:
      if (uVar12 < uVar7) {
        psVar4 = (short *)(iVar10 + iVar11);
      }
      else {
        psVar4 = (short *)0x0;
      }
      if ((*psVar4 == psVar4[2]) && (psVar4[1] == psVar4[3])) {
        uVar6 = 1;
      }
      else {
        uVar6 = 0;
      }
      if ((char)uVar6 == '\0') {
        if (DAT_006a3908 <= uVar12) {
          thunk_FUN_0052b3e0(uVar12 + 1);
          iVar10 = DAT_006a3904;
          uVar7 = DAT_006a390c;
        }
        if (uVar7 <= uVar12) {
          DAT_006a390c = uVar12 + 1;
        }
        CRect::CRect((CRect *)&local_10,(int)*(short *)(iVar10 + iVar11),
                     (int)*(short *)(iVar10 + 2 + iVar11),(int)*(short *)(iVar10 + 4 + iVar11),
                     (int)*(short *)(iVar10 + 6 + iVar11));
        iVar10 = (int)sVar9;
        sVar9 = sVar9 + 1;
        puVar3 = (undefined4 *)(*(int *)(g_pActiveMapContextState + 0x10) + iVar10 * 0x10);
        *puVar3 = local_10;
        puVar3[1] = local_c;
        puVar3[2] = local_8;
        puVar3[3] = local_4;
        iVar10 = DAT_006a3904;
        uVar6 = local_8;
        uVar7 = DAT_006a390c;
      }
      uVar8 = (undefined2)((uint)uVar6 >> 0x10);
      uVar12 = uVar12 + 1;
      iVar11 = iVar11 + 0x18;
    } while (uVar12 < uVar7);
  }
  thunk_FUN_00562d90(CONCAT22(uVar8,*(undefined2 *)(param_1 + 0x2a4)));
  uVar12 = 0;
  if (0 < (int)DAT_006a390c) {
    iVar10 = 0;
    bVar13 = DAT_006a390c != 0;
    uVar7 = DAT_006a390c;
    do {
      if (bVar13) {
        psVar4 = (short *)(DAT_006a3904 + iVar10);
      }
      else {
        psVar4 = (short *)0x0;
      }
      if ((*psVar4 == psVar4[2]) && (psVar4[1] == psVar4[3])) {
        bVar13 = true;
      }
      else {
        bVar13 = false;
      }
      if (!bVar13) {
        if (DAT_006a3908 <= uVar12) {
          thunk_FUN_0052b3e0(uVar12 + 1);
          uVar7 = DAT_006a390c;
        }
        if (uVar7 <= uVar12) {
          uVar7 = uVar12 + 1;
          DAT_006a390c = uVar7;
        }
        if (DAT_006a3908 <= uVar12) {
          thunk_FUN_0052b3e0(uVar12 + 1);
          uVar7 = DAT_006a390c;
        }
        if (uVar7 <= uVar12) {
          DAT_006a390c = uVar12 + 1;
        }
        iVar11 = DAT_006a3904 + iVar10;
        uVar6 = thunk_FUN_00563330(*(undefined2 *)(DAT_006a3904 + 0x12 + iVar10));
        thunk_FUN_00563330(CONCAT22(extraout_var_01,*(undefined2 *)(iVar11 + 0x10)));
        thunk_FUN_0055f300(uVar6);
        iVar11 = thunk_FUN_0052b460(uVar12);
        uVar6 = thunk_FUN_00563330(*(undefined2 *)(iVar11 + 0x10));
        iVar11 = thunk_FUN_0052b460(uVar12);
        thunk_FUN_00563330(CONCAT22(extraout_var_00,*(undefined2 *)(iVar11 + 0x12)));
        thunk_FUN_0055f300(uVar6);
        uVar7 = DAT_006a390c;
      }
      uVar12 = uVar12 + 1;
      iVar10 = iVar10 + 0x18;
      bVar13 = uVar12 < uVar7;
    } while ((int)uVar12 < (int)uVar7);
  }
  thunk_FUN_00563da0();
  thunk_FUN_00563220();
  return;
}

