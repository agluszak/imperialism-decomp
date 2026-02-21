
void __thiscall FUN_004e3830(int *param_1,undefined4 param_2)

{
  short *psVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined4 *unaff_FS_OFFSET;
  int local_20;
  int *local_1c;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  int local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_006324c8;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  InitializeSharedStringRefFromEmpty();
  iVar8 = 0;
  local_4 = 0;
  InitializeNationStateIdentityAndOwnedRegionList(param_2);
  *(undefined2 *)(param_1 + 0x4c) = 0;
  *(undefined2 *)(param_1 + 0x4b) = 0xfff6;
  *(undefined2 *)((int)param_1 + 0x12e) = 0xfff6;
  *(undefined2 *)((int)param_1 + 0x132) = 0;
  piVar3 = param_1 + 0x3c;
  iVar6 = 0x17;
  piVar5 = param_1 + 0x66;
  do {
    *(undefined2 *)((int)piVar3 + -0x2e) = 0;
    *(undefined2 *)piVar3 = 0;
    *(undefined2 *)(piVar3 + -0x17) = 0;
    *(undefined2 *)(piVar3 + 0x13) = 0;
    iVar9 = 0;
    *(undefined2 *)((int)piVar3 + 0x7a) = 0;
    *piVar5 = 0;
    piVar3 = (int *)((int)piVar3 + 2);
    piVar5[1] = 0;
    iVar6 = iVar6 + -1;
    piVar5[2] = 0;
    *(undefined2 *)(piVar5 + 3) = 0;
    piVar5 = (int *)((int)piVar5 + 0xe);
  } while (iVar6 != 0);
  local_20 = 0x1950;
  iVar6 = g_pGlobalMapState;
  do {
    if ((short)*(char *)(*(int *)(iVar6 + 0xc) + 4 + iVar9) == (short)param_1[3]) {
      iVar7 = 0;
      local_1c = (int *)0x2;
      do {
        iVar4 = *(int *)(iVar6 + 0xc) + iVar9;
        cVar2 = *(char *)(iVar7 + 0x11 + iVar4);
        if ((*(char *)(iVar4 + 0x13) != '\x0f') && (cVar2 != -1)) {
          psVar1 = (short *)((int)param_1 + cVar2 * 2 + 0x94);
          *psVar1 = *psVar1 + 1;
          psVar1 = (short *)((int)param_1 + cVar2 * 2 + 0x13c);
          *psVar1 = *psVar1 + 1;
          iVar6 = g_pGlobalMapState;
        }
        iVar7 = iVar7 + 1;
        local_1c = (int *)((int)local_1c + -1);
      } while (local_1c != (int *)0x0);
    }
    iVar9 = iVar9 + 0x24;
    local_20 = local_20 + -1;
  } while (local_20 != 0);
  if ((DAT_006a43f0 == '\0') &&
     ((cVar2 = (**(code **)(*param_1 + 0xa0))(), cVar2 == '\0' ||
      (*(short *)(g_pLocalizationTable + 0x114) != 0)))) {
    local_20 = -1;
    local_1c = (int *)AllocateWithFallbackHandler(0x1c);
    if (local_1c == (int *)0x0) {
      local_1c = (int *)0x0;
    }
    else {
      local_1c[3] = 0;
      local_1c[4] = 0;
      local_1c[2] = 0;
      local_1c[1] = 0;
      local_1c[5] = 0;
      local_1c[6] = 10;
      *local_1c = (int)&PTR_LAB_00650a08;
    }
    iVar9 = 0;
    iVar6 = 0;
    do {
      if (*(char *)(*(int *)(g_pGlobalMapState + 0xc) + 4 + iVar6) == (short)param_2) {
        if ((*(byte *)(*(int *)(g_pGlobalMapState + 0xc) + iVar6 + 0x1c) & 1) != 0) {
          local_20 = iVar9;
        }
        cVar2 = thunk_FUN_00513980(iVar9);
        if (cVar2 != '\0') {
          (**(code **)(*local_1c + 0x14))(iVar8);
        }
      }
      iVar9 = iVar9 + 1;
      iVar8 = iVar8 + 1;
      iVar6 = iVar6 + 0x24;
    } while ((short)iVar9 < 0x1950);
    if ((short)local_20 == -1) {
      iVar6 = *local_1c;
      iVar8 = (**(code **)(iVar6 + 0x28))();
      iVar9 = GenerateThreadLocalRandom15();
      local_20 = (**(code **)(iVar6 + 0x24))(iVar9 % iVar8 + 1);
    }
    InitializeSharedStringRefFromEmpty();
    local_4._0_1_ = 1;
    InitializeSharedStringRefFromEmpty();
    local_4 = CONCAT31(local_4._1_3_,2);
    ResetTileToBaseTransportFlag(local_20);
    param_1[0x22] = (int)(short)local_20;
    if (local_1c != (int *)0x0) {
      (**(code **)(*local_1c + 0x38))();
    }
    thunk_EnsurePortZoneForTile((short)param_1[0x22]);
    local_4._0_1_ = 1;
    ReleaseSharedStringRefIfNotEmpty();
    local_4 = (uint)local_4._1_3_ << 8;
    ReleaseSharedStringRefIfNotEmpty();
  }
  *(undefined2 *)((int)param_1 + 0xa2) = 5;
  switch((short)param_2) {
  case 7:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x44c;
    *(undefined2 *)(param_1 + 0x48) = 0x23a;
    *(undefined2 *)((int)param_1 + 0x122) = 0xc3;
    *(undefined2 *)(param_1 + 0x49) = 0x5a;
    *(undefined2 *)((int)param_1 + 0x126) = 0x69;
    *(undefined2 *)(param_1 + 0x4a) = 0x8a;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x90;
    break;
  case 8:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x47e;
    *(undefined2 *)(param_1 + 0x48) = 0x249;
    *(undefined2 *)((int)param_1 + 0x122) = 0xaf;
    *(undefined2 *)(param_1 + 0x49) = 0x52;
    *(undefined2 *)((int)param_1 + 0x126) = 0x75;
    *(undefined2 *)(param_1 + 0x4a) = 0x72;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x84;
    break;
  case 9:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x4b0;
    *(undefined2 *)(param_1 + 0x48) = 600;
    *(undefined2 *)((int)param_1 + 0x122) = 0x9b;
    *(undefined2 *)(param_1 + 0x49) = 0x4a;
    *(undefined2 *)((int)param_1 + 0x126) = 0x81;
    *(undefined2 *)(param_1 + 0x4a) = 0x7e;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x78;
    break;
  case 10:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x4e2;
    *(undefined2 *)(param_1 + 0x48) = 0x267;
    *(undefined2 *)((int)param_1 + 0x122) = 0x87;
    *(undefined2 *)(param_1 + 0x49) = 0x42;
    *(undefined2 *)((int)param_1 + 0x126) = 0x8d;
    *(undefined2 *)(param_1 + 0x4a) = 0x90;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x6f;
    break;
  case 0xb:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x514;
    *(undefined2 *)(param_1 + 0x48) = 0x276;
    *(undefined2 *)((int)param_1 + 0x122) = 0xbe;
    *(undefined2 *)(param_1 + 0x49) = 0x58;
    *(undefined2 *)((int)param_1 + 0x126) = 0x6c;
    *(undefined2 *)(param_1 + 0x4a) = 0x8d;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x93;
    goto LAB_004e3ce6;
  case 0xc:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x546;
    *(undefined2 *)(param_1 + 0x48) = 0x285;
    *(undefined2 *)((int)param_1 + 0x122) = 0xaa;
    *(undefined2 *)(param_1 + 0x49) = 0x50;
    *(undefined2 *)((int)param_1 + 0x126) = 0x78;
    *(undefined2 *)(param_1 + 0x4a) = 0x69;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x87;
    goto LAB_004e3ce6;
  case 0xd:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x578;
    *(undefined2 *)(param_1 + 0x48) = 0x294;
    *(undefined2 *)((int)param_1 + 0x122) = 0x96;
    *(undefined2 *)(param_1 + 0x49) = 0x48;
    *(undefined2 *)((int)param_1 + 0x126) = 0x84;
    *(undefined2 *)(param_1 + 0x4a) = 0x7b;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x75;
    goto LAB_004e3ce6;
  case 0xe:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x5aa;
    *(undefined2 *)(param_1 + 0x48) = 0x2a3;
    *(undefined2 *)((int)param_1 + 0x122) = 0x82;
    *(undefined2 *)(param_1 + 0x49) = 0x40;
    *(undefined2 *)((int)param_1 + 0x126) = 0x90;
    *(undefined2 *)(param_1 + 0x4a) = 0x81;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x72;
LAB_004e3ce6:
    *(undefined2 *)(param_1 + 0x4d) = 0xb;
    *(undefined2 *)((int)param_1 + 0x136) = 0xc;
    *(undefined2 *)(param_1 + 0x4e) = 0xd;
    *(undefined2 *)((int)param_1 + 0x13a) = 0xe;
    goto switchD_004e3aa6_default;
  case 0xf:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x5dc;
    *(undefined2 *)(param_1 + 0x48) = 0x2b2;
    *(undefined2 *)((int)param_1 + 0x122) = 0xb9;
    *(undefined2 *)(param_1 + 0x49) = 0x56;
    *(undefined2 *)((int)param_1 + 0x126) = 0x6f;
    *(undefined2 *)(param_1 + 0x4a) = 0x93;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x96;
    goto LAB_004e3e17;
  case 0x10:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x60e;
    *(undefined2 *)(param_1 + 0x48) = 0x2c1;
    *(undefined2 *)((int)param_1 + 0x122) = 0xa5;
    *(undefined2 *)(param_1 + 0x49) = 0x4e;
    *(undefined2 *)((int)param_1 + 0x126) = 0x7b;
    *(undefined2 *)(param_1 + 0x4a) = 0x6c;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x8a;
    goto LAB_004e3e17;
  case 0x11:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x640;
    *(undefined2 *)(param_1 + 0x48) = 0x2d0;
    *(undefined2 *)((int)param_1 + 0x122) = 0x91;
    *(undefined2 *)(param_1 + 0x49) = 0x46;
    *(undefined2 *)((int)param_1 + 0x126) = 0x87;
    *(undefined2 *)(param_1 + 0x4a) = 0x78;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x7e;
    goto LAB_004e3e17;
  case 0x12:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x672;
    *(undefined2 *)(param_1 + 0x48) = 0x2df;
    *(undefined2 *)((int)param_1 + 0x122) = 0x7d;
    *(undefined2 *)(param_1 + 0x49) = 0x3e;
    *(undefined2 *)((int)param_1 + 0x126) = 0x93;
    *(undefined2 *)(param_1 + 0x4a) = 0x84;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x69;
LAB_004e3e17:
    *(undefined2 *)(param_1 + 0x4d) = 0xf;
    *(undefined2 *)((int)param_1 + 0x136) = 0x10;
    *(undefined2 *)(param_1 + 0x4e) = 0x11;
    *(undefined2 *)((int)param_1 + 0x13a) = 0x12;
    goto switchD_004e3aa6_default;
  case 0x13:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x6a4;
    *(undefined2 *)(param_1 + 0x48) = 0x2ee;
    *(undefined2 *)((int)param_1 + 0x122) = 0xb4;
    *(undefined2 *)(param_1 + 0x49) = 0x54;
    *(undefined2 *)((int)param_1 + 0x126) = 0x72;
    *(undefined2 *)(param_1 + 0x4a) = 0x96;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x8d;
    goto LAB_004e3f46;
  case 0x14:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x6d6;
    *(undefined2 *)(param_1 + 0x48) = 0x2fd;
    *(undefined2 *)((int)param_1 + 0x122) = 0xa0;
    *(undefined2 *)(param_1 + 0x49) = 0x4c;
    *(undefined2 *)((int)param_1 + 0x126) = 0x7e;
    *(undefined2 *)(param_1 + 0x4a) = 0x6f;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x81;
    goto LAB_004e3f46;
  case 0x15:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x708;
    *(undefined2 *)(param_1 + 0x48) = 0x302;
    *(undefined2 *)((int)param_1 + 0x122) = 0x8c;
    *(undefined2 *)(param_1 + 0x49) = 0x44;
    *(undefined2 *)((int)param_1 + 0x126) = 0x8a;
    *(undefined2 *)(param_1 + 0x4a) = 0x7b;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x75;
    goto LAB_004e3f46;
  case 0x16:
    *(undefined2 *)((int)param_1 + 0x11e) = 0x73a;
    *(undefined2 *)(param_1 + 0x48) = 0x311;
    *(undefined2 *)((int)param_1 + 0x122) = 0x78;
    *(undefined2 *)(param_1 + 0x49) = 0x3c;
    *(undefined2 *)((int)param_1 + 0x126) = 0x96;
    *(undefined2 *)(param_1 + 0x4a) = 0x87;
    *(undefined2 *)((int)param_1 + 0x12a) = 0x6c;
LAB_004e3f46:
    *(undefined2 *)(param_1 + 0x4d) = 0x13;
    *(undefined2 *)((int)param_1 + 0x136) = 0x14;
    *(undefined2 *)(param_1 + 0x4e) = 0x15;
    *(undefined2 *)((int)param_1 + 0x13a) = 0x16;
  default:
    goto switchD_004e3aa6_default;
  }
  *(undefined2 *)(param_1 + 0x4d) = 7;
  *(undefined2 *)((int)param_1 + 0x136) = 8;
  *(undefined2 *)(param_1 + 0x4e) = 9;
  *(undefined2 *)((int)param_1 + 0x13a) = 10;
switchD_004e3aa6_default:
  local_4 = 0xffffffff;
  ReleaseSharedStringRefIfNotEmpty();
  *unaff_FS_OFFSET = uStack_c;
  return;
}

