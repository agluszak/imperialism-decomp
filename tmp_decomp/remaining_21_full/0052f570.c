// 0x0052f570 FUN_0052f570\n\n
void __fastcall FUN_0052f570(int param_1)

{
  int iVar1;
  code *pcVar2;
  bool bVar3;
  CObArray *this;
  short *psVar4;
  undefined2 *puVar5;
  short *psVar6;
  short sVar7;
  undefined4 *unaff_FS_OFFSET;
  int local_20;
  short local_14;
  short local_12;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_006340da;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  this = (CObArray *)AllocateWithFallbackHandler(0x18);
  sVar7 = 0;
  local_4 = 0;
  if (this == (CObArray *)0x0) {
    this = (CObArray *)0x0;
  }
  else {
    CObArray::CObArray(this);
    *(undefined ***)this = &PTR_thunk_GetTIndexAndRankListTypeName_00659c58;
  }
  local_4 = 0xffffffff;
  *(undefined2 *)(this + 0x14) = 6;
  psVar6 = (short *)(param_1 + 0x1e);
  do {
    if (*psVar6 != 0) {
      local_12 = *psVar6 + 1;
      local_14 = sVar7;
      (**(code **)(*(int *)this + 0x38))(&local_14);
    }
    sVar7 = sVar7 + 1;
    psVar6 = psVar6 + 1;
  } while (sVar7 < 0x11);
  local_20 = 4;
  psVar6 = (short *)(param_1 + 0x40);
  iVar1 = local_20;
  do {
    local_20 = iVar1;
    sVar7 = 1;
    bVar3 = false;
    if (0 < *(int *)(this + 8)) {
      do {
        if (bVar3) goto LAB_0052f659;
        psVar4 = (short *)(**(code **)(*(int *)this + 0x2c))((int)sVar7);
        if (*psVar4 == *psVar6) {
          bVar3 = true;
        }
        sVar7 = sVar7 + 1;
      } while ((int)sVar7 <= *(int *)(this + 8));
    }
    if (!bVar3) {
      local_14 = *psVar6;
      local_12 = 1;
      (**(code **)(*(int *)this + 0x38))(&local_14);
    }
LAB_0052f659:
    psVar6 = psVar6 + 1;
    iVar1 = local_20 + -1;
    if (local_20 + -1 == 0) {
      iVar1 = *(int *)this;
      pcVar2 = *(code **)(iVar1 + 0x2c);
      puVar5 = (undefined2 *)(*pcVar2)(1);
      uRam00000000 = *puVar5;
      puVar5 = (undefined2 *)(*pcVar2)(2);
      *(undefined2 *)(local_20 + 0x41) = *puVar5;
      puVar5 = (undefined2 *)(*pcVar2)(3);
      *(undefined2 *)(local_20 + 0x43) = *puVar5;
      puVar5 = (undefined2 *)(*pcVar2)(4);
      *(undefined2 *)(local_20 + 0x45) = *puVar5;
      if (this != (CObArray *)0x0) {
        (**(code **)(iVar1 + 0x24))();
      }
      *unaff_FS_OFFSET = (short *)(param_1 + 0x40);
      return;
    }
  } while( true );
}

