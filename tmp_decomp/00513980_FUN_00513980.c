
char __thiscall FUN_00513980(int param_1,undefined4 param_2)

{
  char cVar1;
  short sVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int extraout_EDX;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  char local_29;
  int local_28;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  short local_c;
  int local_8;
  int local_4;
  
  iVar4 = (int)(short)param_2;
  local_4 = iVar4 * 0x24;
  pcVar3 = (char *)(local_4 + *(int *)(param_1 + 0xc));
  local_29 = '\0';
  cVar1 = *pcVar3;
  local_c = (short)pcVar3[4];
  local_20 = param_1;
  if ((cVar1 == '\x03') || (cVar1 == '\x02')) {
    local_29 = '\0';
  }
  else {
    iVar8 = iVar4 / 0x6c;
    local_14 = 0;
    uVar6 = (int)(short)iVar8 >> 0x1f;
    iVar4 = ((((int)(short)iVar8 ^ uVar6) - uVar6 & 1 ^ uVar6) - uVar6) + (iVar4 % 0x6c) * 2;
    local_10 = iVar4;
    local_8 = iVar8;
    do {
      iVar9 = local_14;
      sVar2 = (short)local_14;
      if (sVar2 < 0) {
        sVar2 = sVar2 + 6;
      }
      else if (5 < sVar2) {
        sVar2 = sVar2 + -6;
      }
      local_1c = local_10 +
                 CONCAT22((short)((uint)iVar4 >> 0x10),*(undefined2 *)(&DAT_00696e70 + sVar2 * 2));
      local_28 = iVar8;
      iVar4 = thunk_FUN_005128f0(local_14);
      local_28 = local_28 + iVar4;
      thunk_FUN_00513120(&local_1c,&local_28);
      uVar10 = thunk_FUN_00512850(local_1c,local_28);
      iVar4 = (int)((ulonglong)uVar10 >> 0x20);
      sVar2 = (short)uVar10;
      if ((sVar2 < 0) || (0x194f < sVar2)) {
        sVar2 = -1;
      }
      if (sVar2 != -1) {
        iVar4 = *(int *)(param_1 + 0xc);
        iVar5 = (int)sVar2;
        if (*(char *)(iVar5 * 0x24 + iVar4) == '\x05') {
          iVar8 = 0;
          local_29 = '\x01';
          uVar6 = (uint)(short)(iVar5 / 0x6c);
          uVar7 = (int)uVar6 >> 0x1f;
          do {
            if ((short)iVar8 < 0) {
              iVar4 = iVar8 + 6;
            }
            else {
              iVar4 = iVar8;
              if (5 < (short)iVar8) {
                iVar4 = iVar8 + -6;
              }
            }
            local_18 = (((uVar6 ^ uVar7) - uVar7 & 1 ^ uVar7) - uVar7) + (iVar5 % 0x6c) * 2 +
                       CONCAT22((short)((uint)iVar4 >> 0x10),
                                *(undefined2 *)(&DAT_00696e70 + (short)iVar4 * 2));
            local_24 = iVar5 / 0x6c;
            iVar4 = thunk_FUN_005128f0(iVar8);
            local_24 = local_24 + iVar4;
            thunk_FUN_00513120(&local_18,&local_24);
            sVar2 = thunk_FUN_00512850(local_18,local_24);
            if ((sVar2 < 0) || (0x194f < sVar2)) {
              sVar2 = -1;
            }
            iVar4 = extraout_EDX;
            if (sVar2 != -1) {
              iVar4 = sVar2 * 9;
              cVar1 = *(char *)(*(int *)(local_20 + 0xc) + 4 + sVar2 * 0x24);
              if ((cVar1 < '\x17') &&
                 (iVar4 = CONCAT22((short)((uint)iVar4 >> 0x10),(short)cVar1), cVar1 != local_c)) {
                local_29 = '\0';
                break;
              }
            }
            iVar8 = iVar8 + 1;
          } while (iVar8 < 6);
          if (*(char *)(*(int *)(g_pGlobalMapState + 0xc) + 0x16 + iVar5 * 0x24) != -1) {
            local_29 = '\0';
          }
          param_1 = local_20;
          iVar9 = local_14;
          iVar8 = local_8;
          if (local_29 != '\0') break;
        }
      }
      local_14 = iVar9 + 1;
    } while ((short)local_14 < 6);
  }
  if (((local_29 == '\0') && (*(char *)(local_4 + 2 + *(int *)(param_1 + 0xc)) != '\0')) &&
     (cVar1 = thunk_FUN_00563b70(param_2), cVar1 == '\0')) {
    local_29 = '\x01';
  }
  return local_29;
}

