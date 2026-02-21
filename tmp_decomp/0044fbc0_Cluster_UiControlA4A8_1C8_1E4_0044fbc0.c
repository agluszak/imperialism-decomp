
int * Cluster_UiControlA4A8_1C8_1E4_0044fbc0(undefined4 param_1,short param_2)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  int *unaff_FS_OFFSET;
  undefined4 uVar7;
  undefined1 **ppuStack_2f0;
  int iStack_2ec;
  undefined1 *puStack_2c8;
  undefined4 uStack_2c4;
  undefined1 *puStack_2b0;
  undefined4 uStack_2ac;
  undefined1 *puStack_298;
  undefined4 uStack_294;
  undefined1 **ppuStack_280;
  int iStack_27c;
  undefined1 *puStack_258;
  undefined4 uStack_254;
  undefined1 *puStack_240;
  undefined4 uStack_23c;
  undefined1 *puStack_228;
  undefined4 uStack_224;
  undefined1 **ppuStack_210;
  int iStack_20c;
  undefined1 *puStack_1e8;
  undefined4 uStack_1e4;
  undefined1 *puStack_1d0;
  undefined4 uStack_1cc;
  undefined1 *puStack_1b8;
  undefined4 uStack_1b4;
  undefined1 **ppuStack_1a0;
  int iStack_19c;
  undefined1 *puStack_178;
  undefined4 uStack_174;
  undefined1 *puStack_160;
  undefined4 uStack_15c;
  undefined1 *puStack_148;
  undefined4 uStack_144;
  undefined1 **ppuStack_130;
  int iStack_12c;
  undefined1 *puStack_108;
  undefined4 uStack_104;
  undefined1 *puStack_f0;
  undefined4 uStack_ec;
  undefined1 *puStack_d8;
  undefined4 uStack_d4;
  undefined4 ****ppppuStack_c0;
  int iStack_bc;
  undefined4 ***pppuStack_98;
  undefined4 uStack_94;
  int **ppiStack_70;
  undefined1 *puStack_6c;
  undefined1 *puStack_58;
  undefined4 uStack_54;
  undefined4 uStack_50;
  int *piStack_4c;
  int *piStack_48;
  int *piStack_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  int *piStack_38;
  int local_24 [6];
  int local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_c = *unaff_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0062bcba;
  *unaff_FS_OFFSET = (int)&local_c;
  g_pUiResourceHead = (int *)0x0;
  if (param_2 == 0x23f7) {
    piStack_38 = (int *)0xa0;
    uStack_3c = 0x44fc09;
    iVar2 = AllocateWithFallbackHandler();
    local_4 = 0;
    if (iVar2 == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piStack_38 = (int *)0x44fc1f;
      piVar3 = (int *)thunk_ConstructUiWindowResourceEntryType4B340();
    }
    local_4 = 0xffffffff;
    if (g_pUiResourceHead == (int *)0x0) {
      uVar6 = 0;
      g_pUiResourceHead = piVar3;
    }
    else {
      uVar6 = *(undefined4 *)(DAT_006a13e8 + 8);
    }
    uStack_3c = 0x44fc59;
    g_pUiResourceContext = piVar3;
    piStack_38 = piVar3;
    thunk_PushUiResourcePoolNode();
    piStack_38 = (int *)0x1;
    uStack_3c = 0;
    piStack_44 = local_24;
    uStack_40 = 0;
    piStack_48 = local_24 + 2;
    uStack_50 = 0;
    local_24[0] = 0x172;
    local_24[1] = 0x19a;
    local_24[2] = 0x7d;
    local_24[3] = 0x3e;
    uStack_54 = 0x44fc91;
    piStack_4c = (int *)uVar6;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piStack_38 = (int *)0x0;
    uStack_3c = 1;
    piVar3[7] = 0x57494e44;
    piVar3[0xf] = 0;
    uStack_40 = 0x44fca8;
    (**(code **)(iVar2 + 0xa4))();
    uStack_40 = 0;
    piStack_44 = (int *)0x1;
    piStack_48 = (int *)0x44fcb3;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x1c) = 1;
    *(undefined1 *)((int)piVar3 + 0x6f) = 1;
    *(undefined1 *)((int)piVar3 + 0x6e) = 1;
    *(undefined1 *)((int)piVar3 + 0x6d) = 1;
    *(undefined1 *)(piVar3 + 0x1b) = 0;
    *(undefined1 *)((int)piVar3 + 0x71) = 1;
    *(undefined2 *)(piVar3 + 0x27) = 0x80;
    *(undefined2 *)(piVar3 + 0x18) = 8000;
    pcVar1 = *(code **)(*g_pUiResourceContext + 0x1b8);
    piStack_48 = (int *)0x44fcfd;
    piVar3 = (int *)(*pcVar1)();
    piStack_48 = (int *)0x1;
    piStack_4c = (int *)0x44fd06;
    (**(code **)(*piVar3 + 0x30))();
    piStack_4c = (int *)0x20202020;
    uStack_50 = 0x20202020;
    uStack_54 = 0;
    puStack_58 = (undefined1 *)0x44fd15;
    (*pcVar1)();
    puStack_58 = (undefined1 *)0x44fd1c;
    thunk_SetUiColorDescriptorGoldTriplet();
    piStack_4c = (int *)0xcc;
    g_pUiResourceContext = (int *)0x0;
    uStack_50 = 0x44fd2c;
    local_c = AllocateWithFallbackHandler();
    local_24[3] = 1;
    if (local_c == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piStack_4c = (int *)0x44fd46;
      piVar3 = (int *)thunk_FUN_004c82c0();
    }
    local_24[3] = 0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    uStack_50 = 0x44fd80;
    g_pUiResourceContext = piVar3;
    piStack_4c = piVar3;
    thunk_PushUiResourcePoolNode();
    piStack_4c = (int *)0x1;
    uStack_50 = 0;
    puStack_58 = &stack0xffffffd0;
    uStack_54 = 0;
    piStack_38 = (int *)0x0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piStack_4c = (int *)0x0;
    uStack_50 = 1;
    piVar3[7] = 0x444c4f47;
    piVar3[0xf] = 0;
    uStack_54 = 0x44fdc2;
    (**(code **)(iVar2 + 0xa4))();
    uStack_54 = 0;
    puStack_58 = (undefined1 *)0x0;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    puStack_6c = (undefined1 *)0x44fdf3;
    piVar4 = (int *)CRect::CRect((CRect *)&uStack_40,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    local_24[0] = AllocateWithFallbackHandler();
    if (local_24[0] == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructUiResourceEntryType4B0C0();
    }
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    ppiStack_70 = &piStack_48;
    puStack_6c = (undefined1 *)0x0;
    piStack_48 = (int *)0x172;
    piStack_44 = (int *)0xb4;
    uStack_50 = 0;
    piStack_4c = (int *)0xe6;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x73656c65;
    piVar3[0xf] = 0;
    puStack_6c = (undefined1 *)0x44feca;
    (**(code **)(iVar2 + 0xa4))();
    puStack_6c = (undefined1 *)0x0;
    ppiStack_70 = (int **)0x0;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 5;
    piVar4 = (int *)CRect::CRect((CRect *)&puStack_58,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    g_pUiResourceContext[0x21] = 0x20202020;
    g_pUiResourceContext = (int *)0x0;
    piVar3 = (int *)AllocateWithFallbackHandler();
    uStack_40 = 3;
    if (piVar3 == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      thunk_ConstructUiClickablePictureResourceEntry();
      *piVar3 = (int)&PTR_LAB_00643a40;
      piVar3[0x26] = 0;
    }
    uStack_40 = 0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_58 = (undefined1 *)0x59;
    uStack_54 = 0x4e;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x62757430;
    piVar3[0xf] = 0;
    (**(code **)(iVar2 + 0xa4))();
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xc;
    uStack_94 = 0x450010;
    piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff98,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    piStack_4c = (int *)AllocateWithFallbackHandler();
    puStack_58 = (undefined1 *)0x4;
    if (piStack_4c == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructUiResourceEntryType4B0C0();
    }
    puStack_58 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    pppuStack_98 = &ppiStack_70;
    uStack_94 = 0;
    ppiStack_70 = (int **)0x53;
    puStack_6c = (undefined1 *)0x16;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x636c7530;
    piVar3[0xf] = 0;
    uStack_94 = 0x4500f5;
    (**(code **)(iVar2 + 0xa4))();
    uStack_94 = 0;
    pppuStack_98 = (undefined4 ***)0x0;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 5;
    piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff80,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    g_pUiResourceContext[0x21] = 0x20202020;
    g_pUiResourceContext = (int *)0x0;
    piVar3 = (int *)AllocateWithFallbackHandler();
    if (piVar3 == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      thunk_ConstructUiNumericTextEntryBase();
      piVar3[0x28] = 0;
      *piVar3 = (int)&g_vtblFamily_NumericEntryDialogCore_Root;
    }
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x6e756d62;
    piVar3[0xf] = 0;
    (**(code **)(iVar2 + 0xa4))();
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 0;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 6;
    iStack_bc = 0x45023e;
    piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff70,3,3,3,3);
    piVar3[0x1a] = *piVar4;
    puStack_6c = &stack0xffffff50;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    thunk_SetUiResourceContextTagWord();
    iStack_bc = 3;
    ppppuStack_c0 = (undefined4 ****)&DAT_00694378;
    thunk_BindUiResourceTextAndStyle();
    piVar3 = g_pUiResourceContext;
    (**(code **)(*g_pUiResourceContext + 0xc))();
    *(undefined2 *)(piVar3 + 0x27) = 0xff;
    piVar3 = g_pUiResourceContext;
    iVar2 = *g_pUiResourceContext;
    (**(code **)(iVar2 + 0xc))();
    piVar3[0x29] = 0;
    piVar3[0x2a] = 0xff;
    (**(code **)(iVar2 + 0x1e4))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    if (iVar2 == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    ppppuStack_c0 = &pppuStack_98;
    iStack_bc = 0;
    pppuStack_98 = (undefined4 ***)0x14;
    uStack_94 = 0x14;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x6d696e75;
    piVar3[0xf] = 0;
    iStack_bc = 0x450365;
    (**(code **)(iVar2 + 0xa4))();
    iStack_bc = 0;
    ppppuStack_c0 = (undefined4 ****)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    uStack_d4 = 0x450397;
    piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff58,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    pppuStack_98 = (undefined4 ***)0x7;
    if (iVar2 == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    pppuStack_98 = (undefined4 ***)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_d8 = &stack0xffffff50;
    uStack_d4 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x706c7573;
    piVar3[0xf] = 0;
    uStack_d4 = 0x450474;
    (**(code **)(iVar2 + 0xa4))();
    uStack_d4 = 0;
    puStack_d8 = (undefined1 *)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    uStack_ec = 0x4504a6;
    piVar4 = (int *)CRect::CRect((CRect *)&ppppuStack_c0,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    piVar3 = (int *)AllocateWithFallbackHandler();
    if (piVar3 == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      thunk_ConstructUiClickablePictureResourceEntry();
      *piVar3 = (int)&PTR_LAB_00643a40;
      piVar3[0x26] = 0;
    }
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_f0 = &stack0xffffff38;
    uStack_ec = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x62757431;
    piVar3[0xf] = 0;
    uStack_ec = 0x4505a5;
    (**(code **)(iVar2 + 0xa4))();
    uStack_ec = 0;
    puStack_f0 = (undefined1 *)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xc;
    uStack_104 = 0x4505d7;
    piVar4 = (int *)CRect::CRect((CRect *)&puStack_d8,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_bc = AllocateWithFallbackHandler();
    if (iStack_bc == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructUiResourceEntryType4B0C0();
    }
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_108 = &stack0xffffff20;
    uStack_104 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x636c7531;
    piVar3[0xf] = 0;
    uStack_104 = 0x4506c0;
    (**(code **)(iVar2 + 0xa4))();
    uStack_104 = 0;
    puStack_108 = (undefined1 *)0x0;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 5;
    piVar4 = (int *)CRect::CRect((CRect *)&puStack_f0,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    g_pUiResourceContext[0x21] = 0x20202020;
    g_pUiResourceContext = (int *)0x0;
    piVar3 = (int *)AllocateWithFallbackHandler();
    puStack_d8 = (undefined1 *)0xa;
    if (piVar3 == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      thunk_ConstructUiNumericTextEntryBase();
      piVar3[0x28] = 0;
      *piVar3 = (int)&g_vtblFamily_NumericEntryDialogCore_Root;
    }
    puStack_d8 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_f0 = (undefined1 *)0x14;
    uStack_ec = 0x12;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x6e756d62;
    piVar3[0xf] = 0;
    (**(code **)(iVar2 + 0xa4))();
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 0;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 6;
    iStack_12c = 0x450807;
    piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff00,3,3,3,3);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    thunk_SetUiResourceContextTagWord();
    iStack_12c = 3;
    ppuStack_130 = (undefined1 **)&DAT_00694378;
    thunk_BindUiResourceTextAndStyle();
    piVar3 = g_pUiResourceContext;
    (**(code **)(*g_pUiResourceContext + 0xc))();
    *(undefined2 *)(piVar3 + 0x27) = 0xff;
    piVar3 = g_pUiResourceContext;
    iVar2 = *g_pUiResourceContext;
    (**(code **)(iVar2 + 0xc))();
    piVar3[0x29] = 0;
    piVar3[0x2a] = 0xff;
    (**(code **)(iVar2 + 0x1e4))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    puStack_f0 = (undefined1 *)0xb;
    if (iVar2 == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    puStack_f0 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    ppuStack_130 = &puStack_108;
    iStack_12c = 0;
    puStack_108 = (undefined1 *)0x14;
    uStack_104 = 0x14;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x6d696e75;
    piVar3[0xf] = 0;
    iStack_12c = 0x45092e;
    (**(code **)(iVar2 + 0xa4))();
    iStack_12c = 0;
    ppuStack_130 = (undefined1 **)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    uStack_144 = 0x450960;
    piVar4 = (int *)CRect::CRect((CRect *)&stack0xfffffee8,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    puStack_108 = (undefined1 *)0xc;
    if (iVar2 == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    puStack_108 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_148 = &stack0xfffffee0;
    uStack_144 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x706c7573;
    piVar3[0xf] = 0;
    uStack_144 = 0x450a3d;
    (**(code **)(iVar2 + 0xa4))();
    uStack_144 = 0;
    puStack_148 = (undefined1 *)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    uStack_15c = 0x450a6f;
    piVar4 = (int *)CRect::CRect((CRect *)&ppuStack_130,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    piVar3 = (int *)AllocateWithFallbackHandler();
    if (piVar3 == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      thunk_ConstructUiClickablePictureResourceEntry();
      *piVar3 = (int)&PTR_LAB_00643a40;
      piVar3[0x26] = 0;
    }
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_160 = &stack0xfffffec8;
    uStack_15c = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x62757432;
    piVar3[0xf] = 0;
    uStack_15c = 0x450b6e;
    (**(code **)(iVar2 + 0xa4))();
    uStack_15c = 0;
    puStack_160 = (undefined1 *)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xc;
    uStack_174 = 0x450ba0;
    piVar4 = (int *)CRect::CRect((CRect *)&puStack_148,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_12c = AllocateWithFallbackHandler();
    if (iStack_12c == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructUiResourceEntryType4B0C0();
    }
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_178 = &stack0xfffffeb0;
    uStack_174 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x636c7532;
    piVar3[0xf] = 0;
    uStack_174 = 0x450c89;
    (**(code **)(iVar2 + 0xa4))();
    uStack_174 = 0;
    puStack_178 = (undefined1 *)0x0;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 5;
    piVar4 = (int *)CRect::CRect((CRect *)&puStack_160,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    g_pUiResourceContext[0x21] = 0x20202020;
    g_pUiResourceContext = (int *)0x0;
    piVar3 = (int *)AllocateWithFallbackHandler();
    puStack_148 = (undefined1 *)0xf;
    if (piVar3 == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      thunk_ConstructUiNumericTextEntryBase();
      piVar3[0x28] = 0;
      *piVar3 = (int)&g_vtblFamily_NumericEntryDialogCore_Root;
    }
    puStack_148 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_160 = (undefined1 *)0x14;
    uStack_15c = 0x12;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x6e756d62;
    piVar3[0xf] = 0;
    (**(code **)(iVar2 + 0xa4))();
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 0;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 6;
    iStack_19c = 0x450dd0;
    piVar4 = (int *)CRect::CRect((CRect *)&stack0xfffffe90,3,3,3,3);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    thunk_SetUiResourceContextTagWord();
    iStack_19c = 3;
    ppuStack_1a0 = (undefined1 **)&DAT_00694378;
    thunk_BindUiResourceTextAndStyle();
    piVar3 = g_pUiResourceContext;
    (**(code **)(*g_pUiResourceContext + 0xc))();
    *(undefined2 *)(piVar3 + 0x27) = 0xff;
    piVar3 = g_pUiResourceContext;
    iVar2 = *g_pUiResourceContext;
    (**(code **)(iVar2 + 0xc))();
    piVar3[0x29] = 0;
    piVar3[0x2a] = 0xff;
    (**(code **)(iVar2 + 0x1e4))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    puStack_160 = (undefined1 *)0x10;
    if (iVar2 == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    puStack_160 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    ppuStack_1a0 = &puStack_178;
    iStack_19c = 0;
    puStack_178 = (undefined1 *)0x14;
    uStack_174 = 0x14;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x6d696e75;
    piVar3[0xf] = 0;
    iStack_19c = 0x450ef7;
    (**(code **)(iVar2 + 0xa4))();
    iStack_19c = 0;
    ppuStack_1a0 = (undefined1 **)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    uStack_1b4 = 0x450f29;
    piVar4 = (int *)CRect::CRect((CRect *)&stack0xfffffe78,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    puStack_178 = (undefined1 *)0x11;
    if (iVar2 == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    puStack_178 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_1b8 = &stack0xfffffe70;
    uStack_1b4 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x706c7573;
    piVar3[0xf] = 0;
    uStack_1b4 = 0x451006;
    (**(code **)(iVar2 + 0xa4))();
    uStack_1b4 = 0;
    puStack_1b8 = (undefined1 *)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    uStack_1cc = 0x451038;
    piVar4 = (int *)CRect::CRect((CRect *)&ppuStack_1a0,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    piVar3 = (int *)AllocateWithFallbackHandler();
    if (piVar3 == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      thunk_ConstructUiClickablePictureResourceEntry();
      *piVar3 = (int)&PTR_LAB_00643a40;
      piVar3[0x26] = 0;
    }
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_1d0 = &stack0xfffffe58;
    uStack_1cc = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x62757433;
    piVar3[0xf] = 0;
    uStack_1cc = 0x451137;
    (**(code **)(iVar2 + 0xa4))();
    uStack_1cc = 0;
    puStack_1d0 = (undefined1 *)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xc;
    uStack_1e4 = 0x451169;
    piVar4 = (int *)CRect::CRect((CRect *)&puStack_1b8,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_19c = AllocateWithFallbackHandler();
    if (iStack_19c == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructUiResourceEntryType4B0C0();
    }
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_1e8 = &stack0xfffffe40;
    uStack_1e4 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x636c7533;
    piVar3[0xf] = 0;
    uStack_1e4 = 0x451252;
    (**(code **)(iVar2 + 0xa4))();
    uStack_1e4 = 0;
    puStack_1e8 = (undefined1 *)0x0;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 5;
    piVar4 = (int *)CRect::CRect((CRect *)&puStack_1d0,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    g_pUiResourceContext[0x21] = 0x20202020;
    g_pUiResourceContext = (int *)0x0;
    piVar3 = (int *)AllocateWithFallbackHandler();
    puStack_1b8 = (undefined1 *)0x14;
    if (piVar3 == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      thunk_ConstructUiNumericTextEntryBase();
      piVar3[0x28] = 0;
      *piVar3 = (int)&g_vtblFamily_NumericEntryDialogCore_Root;
    }
    puStack_1b8 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_1d0 = (undefined1 *)0x14;
    uStack_1cc = 0x12;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x6e756d62;
    piVar3[0xf] = 0;
    (**(code **)(iVar2 + 0xa4))();
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 0;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 6;
    iStack_20c = 0x451395;
    piVar4 = (int *)CRect::CRect((CRect *)&stack0xfffffe20,3,3,3,3);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    thunk_SetUiResourceContextTagWord();
    iStack_20c = 3;
    ppuStack_210 = (undefined1 **)&DAT_00694378;
    thunk_BindUiResourceTextAndStyle();
    piVar3 = g_pUiResourceContext;
    (**(code **)(*g_pUiResourceContext + 0xc))();
    *(undefined2 *)(piVar3 + 0x27) = 0xff;
    piVar3 = g_pUiResourceContext;
    iVar2 = *g_pUiResourceContext;
    (**(code **)(iVar2 + 0xc))();
    piVar3[0x29] = 0;
    piVar3[0x2a] = 0xff;
    (**(code **)(iVar2 + 0x1e4))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    puStack_1d0 = (undefined1 *)0x15;
    if (iVar2 == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    puStack_1d0 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    ppuStack_210 = &puStack_1e8;
    iStack_20c = 0;
    puStack_1e8 = (undefined1 *)0x14;
    uStack_1e4 = 0x14;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x6d696e75;
    piVar3[0xf] = 0;
    iStack_20c = 0x4514bc;
    (**(code **)(iVar2 + 0xa4))();
    iStack_20c = 0;
    ppuStack_210 = (undefined1 **)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    uStack_224 = 0x4514ee;
    piVar4 = (int *)CRect::CRect((CRect *)&stack0xfffffe08,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    puStack_1e8 = (undefined1 *)0x16;
    if (iVar2 == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    puStack_1e8 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_228 = &stack0xfffffe00;
    uStack_224 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x706c7573;
    piVar3[0xf] = 0;
    uStack_224 = 0x4515cb;
    (**(code **)(iVar2 + 0xa4))();
    uStack_224 = 0;
    puStack_228 = (undefined1 *)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    uStack_23c = 0x4515fd;
    piVar4 = (int *)CRect::CRect((CRect *)&ppuStack_210,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    piVar3 = (int *)AllocateWithFallbackHandler();
    if (piVar3 == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      thunk_ConstructUiClickablePictureResourceEntry();
      *piVar3 = (int)&PTR_LAB_00643a40;
      piVar3[0x26] = 0;
    }
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_240 = &stack0xfffffde8;
    uStack_23c = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x62757434;
    piVar3[0xf] = 0;
    uStack_23c = 0x4516fc;
    (**(code **)(iVar2 + 0xa4))();
    uStack_23c = 0;
    puStack_240 = (undefined1 *)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xc;
    uStack_254 = 0x45172e;
    piVar4 = (int *)CRect::CRect((CRect *)&puStack_228,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_20c = AllocateWithFallbackHandler();
    if (iStack_20c == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructUiResourceEntryType4B0C0();
    }
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_258 = &stack0xfffffdd0;
    uStack_254 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x636c7534;
    piVar3[0xf] = 0;
    uStack_254 = 0x451817;
    (**(code **)(iVar2 + 0xa4))();
    uStack_254 = 0;
    puStack_258 = (undefined1 *)0x0;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 5;
    piVar4 = (int *)CRect::CRect((CRect *)&puStack_240,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    g_pUiResourceContext[0x21] = 0x20202020;
    g_pUiResourceContext = (int *)0x0;
    piVar3 = (int *)AllocateWithFallbackHandler();
    puStack_228 = (undefined1 *)0x19;
    if (piVar3 == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      thunk_ConstructUiNumericTextEntryBase();
      piVar3[0x28] = 0;
      *piVar3 = (int)&g_vtblFamily_NumericEntryDialogCore_Root;
    }
    puStack_228 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_240 = (undefined1 *)0x14;
    uStack_23c = 0x12;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x6e756d62;
    piVar3[0xf] = 0;
    (**(code **)(iVar2 + 0xa4))();
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 0;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 6;
    iStack_27c = 0x45195e;
    piVar4 = (int *)CRect::CRect((CRect *)&stack0xfffffdb0,3,3,3,3);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    thunk_SetUiResourceContextTagWord();
    iStack_27c = 3;
    ppuStack_280 = (undefined1 **)&DAT_00694378;
    thunk_BindUiResourceTextAndStyle();
    piVar3 = g_pUiResourceContext;
    (**(code **)(*g_pUiResourceContext + 0xc))();
    *(undefined2 *)(piVar3 + 0x27) = 0xff;
    piVar3 = g_pUiResourceContext;
    iVar2 = *g_pUiResourceContext;
    (**(code **)(iVar2 + 0xc))();
    piVar3[0x29] = 0;
    piVar3[0x2a] = 0xff;
    (**(code **)(iVar2 + 0x1e4))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    puStack_240 = (undefined1 *)0x1a;
    if (iVar2 == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    puStack_240 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    ppuStack_280 = &puStack_258;
    iStack_27c = 0;
    puStack_258 = (undefined1 *)0x14;
    uStack_254 = 0x14;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x6d696e75;
    piVar3[0xf] = 0;
    iStack_27c = 0x451a85;
    (**(code **)(iVar2 + 0xa4))();
    iStack_27c = 0;
    ppuStack_280 = (undefined1 **)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    uStack_294 = 0x451ab7;
    piVar4 = (int *)CRect::CRect((CRect *)&stack0xfffffd98,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    puStack_258 = (undefined1 *)0x1b;
    if (iVar2 == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    puStack_258 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_298 = &stack0xfffffd90;
    uStack_294 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x706c7573;
    piVar3[0xf] = 0;
    uStack_294 = 0x451b94;
    (**(code **)(iVar2 + 0xa4))();
    uStack_294 = 0;
    puStack_298 = (undefined1 *)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    uStack_2ac = 0x451bc6;
    piVar4 = (int *)CRect::CRect((CRect *)&ppuStack_280,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    piVar3 = (int *)AllocateWithFallbackHandler();
    if (piVar3 == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      thunk_ConstructUiClickablePictureResourceEntry();
      *piVar3 = (int)&PTR_LAB_00643a40;
      piVar3[0x26] = 0;
    }
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_2b0 = &stack0xfffffd78;
    uStack_2ac = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x62757435;
    piVar3[0xf] = 0;
    uStack_2ac = 0x451cc5;
    (**(code **)(iVar2 + 0xa4))();
    uStack_2ac = 0;
    puStack_2b0 = (undefined1 *)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xc;
    uStack_2c4 = 0x451cf7;
    piVar4 = (int *)CRect::CRect((CRect *)&puStack_298,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_27c = AllocateWithFallbackHandler();
    if (iStack_27c == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructUiResourceEntryType4B0C0();
    }
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_2c8 = &stack0xfffffd60;
    uStack_2c4 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x636c7535;
    piVar3[0xf] = 0;
    uStack_2c4 = 0x451de0;
    (**(code **)(iVar2 + 0xa4))();
    uStack_2c4 = 0;
    puStack_2c8 = (undefined1 *)0x0;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 5;
    piVar4 = (int *)CRect::CRect((CRect *)&puStack_2b0,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    g_pUiResourceContext[0x21] = 0x20202020;
    g_pUiResourceContext = (int *)0x0;
    piVar3 = (int *)AllocateWithFallbackHandler();
    puStack_298 = (undefined1 *)0x1e;
    if (piVar3 == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      thunk_ConstructUiNumericTextEntryBase();
      piVar3[0x28] = 0;
      *piVar3 = (int)&g_vtblFamily_NumericEntryDialogCore_Root;
    }
    puStack_298 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    puStack_2b0 = (undefined1 *)0x14;
    uStack_2ac = 0x12;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x6e756d62;
    piVar3[0xf] = 0;
    (**(code **)(iVar2 + 0xa4))();
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 0;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 6;
    iStack_2ec = 0x451f27;
    piVar4 = (int *)CRect::CRect((CRect *)&stack0xfffffd40,3,3,3,3);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    thunk_SetUiResourceContextTagWord();
    iStack_2ec = 3;
    ppuStack_2f0 = (undefined1 **)&DAT_00694378;
    thunk_BindUiResourceTextAndStyle();
    piVar3 = g_pUiResourceContext;
    (**(code **)(*g_pUiResourceContext + 0xc))();
    *(undefined2 *)(piVar3 + 0x27) = 0xff;
    piVar3 = g_pUiResourceContext;
    iVar2 = *g_pUiResourceContext;
    (**(code **)(iVar2 + 0xc))();
    piVar3[0x29] = 0;
    piVar3[0x2a] = 0xff;
    (**(code **)(iVar2 + 0x1e4))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    puStack_2b0 = (undefined1 *)0x1f;
    if (iVar2 == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    puStack_2b0 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    ppuStack_2f0 = &puStack_2c8;
    iStack_2ec = 0;
    puStack_2c8 = (undefined1 *)0x14;
    uStack_2c4 = 0x14;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x6d696e75;
    piVar3[0xf] = 0;
    iStack_2ec = 0x45204e;
    (**(code **)(iVar2 + 0xa4))();
    iStack_2ec = 0;
    ppuStack_2f0 = (undefined1 **)0x1;
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    piVar4 = (int *)CRect::CRect((CRect *)&stack0xfffffd28,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    puStack_2c8 = (undefined1 *)0x20;
    if (iVar2 == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    puStack_2c8 = (undefined1 *)0xffffffff;
    piVar4 = piVar3;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar4 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar4;
    g_pUiResourceContext = piVar3;
    thunk_PushUiResourcePoolNode();
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar2 = *piVar3;
    piVar3[7] = 0x706c7573;
    piVar3[0xf] = 0;
    (**(code **)(iVar2 + 0xa4))();
    (**(code **)(iVar2 + 0xa8))();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    piVar3 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    piVar4 = (int *)CRect::CRect((CRect *)&ppuStack_2f0,0,0,0,0);
    piVar3[0x1a] = *piVar4;
    piVar3[0x1b] = piVar4[1];
    piVar3[0x1c] = piVar4[2];
    piVar3[0x1d] = piVar4[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    puVar5 = (undefined4 *)AllocateWithFallbackHandler();
    if (puVar5 != (undefined4 *)0x0) {
      thunk_ConstructUiClickablePictureResourceEntry();
      *puVar5 = &PTR_LAB_00643a40;
      puVar5[0x26] = 0;
    }
    thunk_RegisterUiResourceEntry();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    thunk_SetUiResourceLayoutValues();
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    if (iVar2 != 0) {
      thunk_ConstructUiResourceEntryType4B0C0();
    }
    thunk_RegisterUiResourceEntry();
    piVar3 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar3 + 0x4d) = 1;
    thunk_SetUiResourceLayoutValues();
    g_pUiResourceContext[0x21] = 0x20202020;
    g_pUiResourceContext = (int *)0x0;
    iVar2 = AllocateWithFallbackHandler();
    if (iVar2 != 0) {
      thunk_ConstructUiNumericTextEntry();
    }
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    thunk_BindUiResourceTextAndStyle();
    thunk_UpdateUiResourceContextMetricWord27();
    thunk_FUN_0041b5a0();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    if (iVar2 != 0) {
      thunk_ConstructPictureScreenResourceEntry();
    }
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues();
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    ppuStack_2f0 = (undefined1 **)0x25;
    if (iVar2 != 0) {
      thunk_ConstructPictureScreenResourceEntry();
    }
    ppuStack_2f0 = (undefined1 **)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues();
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iStack_2ec = AllocateWithFallbackHandler();
    if (iStack_2ec == 0) {
      uVar6 = 0;
    }
    else {
      uVar6 = thunk_FUN_00453800();
    }
    thunk_RegisterUiResourceEntry(0x70696374,0x62757437,uVar6);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues();
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    if (iVar2 == 0) {
      uVar6 = 0;
    }
    else {
      uVar6 = thunk_ConstructUiResourceEntryType4B0C0();
    }
    thunk_RegisterUiResourceEntry(0x636c7573,0x636c7537,uVar6,0x114,0x94);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues();
    g_pUiResourceContext[0x21] = 0x20202020;
    g_pUiResourceContext = (int *)0x0;
    iVar2 = AllocateWithFallbackHandler();
    if (iVar2 == 0) {
      uVar6 = 0;
    }
    else {
      uVar6 = thunk_ConstructUiNumericTextEntry();
    }
    thunk_RegisterUiResourceEntry(0x6e6d6272,0x6e756d62,uVar6,0x1e,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    thunk_BindUiResourceTextAndStyle(0xffffffff,0xffffffff);
    thunk_UpdateUiResourceContextMetricWord27();
    thunk_FUN_0041b5a0();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    if (iVar2 == 0) {
      uVar6 = 0;
    }
    else {
      uVar6 = thunk_ConstructPictureScreenResourceEntry();
    }
    thunk_RegisterUiResourceEntry(0x70696374,0x6d696e75,uVar6,0,0);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues();
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    if (iVar2 == 0) {
      uVar6 = 0;
    }
    else {
      uVar6 = thunk_ConstructPictureScreenResourceEntry();
    }
    thunk_RegisterUiResourceEntry(0x70696374,0x706c7573,uVar6,0x3c,0,0x14,0x14);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10);
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    if (iVar2 == 0) {
      uVar6 = 0;
    }
    else {
      uVar6 = thunk_ConstructUiTextResourceEntryBase();
    }
    thunk_RegisterUiResourceEntry(0x73746174,0x736e616d,uVar6,0x69,0x37,0xa5,0x13,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(0xd,0,0);
    thunk_SetUiResourceContextTagWord(0);
    thunk_BindUiResourceTextAndStyle(4000,0xffffffff,&DAT_006a13a0,3,1,9);
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    if (iVar2 == 0) {
      uVar6 = 0;
    }
    else {
      uVar6 = thunk_ConstructUiTextResourceEntryBase();
    }
    thunk_RegisterUiResourceEntry(0x73746174,0x66697830,uVar6,0x19,0x84,0x2c,0xe,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(0xd,0,0);
    thunk_SetUiResourceContextTagWord(0);
    thunk_BindUiResourceTextAndStyle(4000,1,s_Cost__006949d8,3,1,0xc);
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    if (iVar2 == 0) {
      uVar6 = 0;
    }
    else {
      uVar6 = thunk_ConstructUiTextResourceEntryBase();
    }
    thunk_RegisterUiResourceEntry(0x73746174,0x66697831,uVar6,0x17,0xb7,0x50,0x11,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(0xd,0,0);
    thunk_SetUiResourceContextTagWord(0);
    thunk_BindUiResourceTextAndStyle(4000,2,s_Available__006949c8,3,1,0xc);
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    if (iVar2 == 0) {
      uVar6 = 0;
    }
    else {
      uVar6 = thunk_ConstructUiTextResourceEntryBase();
    }
    thunk_RegisterUiResourceEntry(0x73746174,0x64657363,uVar6,0xcf,0x7d,0x87,0x68,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(0xd,0,0);
    thunk_SetUiResourceContextTagWord(0);
    thunk_BindUiResourceTextAndStyle(4000,0xffffffff,&DAT_006a13a0,3,0,10);
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    if (iVar2 == 0) {
      uVar6 = 0;
    }
    else {
      uVar6 = thunk_ConstructUiTextResourceEntryBase();
    }
    thunk_RegisterUiResourceEntry(0x73746174,0x7469746c,uVar6,0x54,0xb,200,0x1e,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(0xd,0,0);
    thunk_SetUiResourceContextTagWord(0);
    thunk_BindUiResourceTextAndStyle(4000,4,s_Shipyard_006949bc,3,1,0x18);
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar2 = AllocateWithFallbackHandler();
    if (iVar2 == 0) {
      uVar6 = 0;
    }
    else {
      uVar6 = thunk_ConstructPictureResourceEntryBase();
    }
    uVar7 = 0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x73706963,uVar6,0xe7,0x4a,0x56,0x2d,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    if (g_pUiResourceHead != (int *)0x0) {
      thunk_PropagateUiResourceContextRecursive(uVar7);
    }
    piVar3 = g_pUiResourceHead;
    *unaff_FS_OFFSET = 0x264a;
    return piVar3;
  }
  *unaff_FS_OFFSET = local_c;
  return (int *)0x0;
}

