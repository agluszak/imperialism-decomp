
int * FUN_0046fd10(undefined4 param_1,short param_2)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  undefined4 uVar4;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uVar5;
  undefined1 *puStack_3bc;
  undefined4 uStack_3b8;
  undefined1 *puStack_3a4;
  int iStack_3a0;
  int iVar6;
  undefined1 *puStack_38c;
  int iStack_388;
  undefined1 *puStack_374;
  int iStack_370;
  undefined1 *puStack_35c;
  int iStack_358;
  undefined1 *puStack_344;
  int iStack_340;
  undefined1 *puStack_32c;
  int iStack_328;
  undefined1 *puStack_314;
  int iStack_310;
  undefined1 *puStack_2fc;
  int iStack_2f8;
  undefined1 *puStack_2e4;
  int iStack_2e0;
  undefined1 *puStack_2cc;
  int iStack_2c8;
  undefined1 *puStack_2b4;
  int iStack_2b0;
  undefined1 *puStack_29c;
  int iStack_298;
  undefined1 *puStack_284;
  int iStack_280;
  undefined1 *puStack_26c;
  int iStack_268;
  undefined1 *puStack_254;
  int iStack_250;
  undefined1 *puStack_23c;
  int iStack_238;
  undefined1 *puStack_224;
  int iStack_220;
  undefined1 *puStack_20c;
  int iStack_208;
  undefined1 *puStack_1f4;
  int iStack_1f0;
  undefined1 *puStack_1dc;
  int iStack_1d8;
  undefined1 *puStack_1c4;
  int iStack_1c0;
  undefined1 *puStack_1ac;
  int iStack_1a8;
  undefined1 *puStack_194;
  int iStack_190;
  undefined1 *puStack_17c;
  int iStack_178;
  undefined1 *puStack_164;
  int iStack_160;
  undefined1 *puStack_c4;
  undefined4 uStack_c0;
  undefined1 *puStack_ac;
  undefined4 uStack_a8;
  undefined4 ***pppuStack_94;
  int iStack_90;
  undefined4 **ppuStack_6c;
  undefined4 uStack_68;
  undefined1 *puStack_54;
  undefined4 uStack_50;
  undefined4 uStack_4c;
  int *piStack_48;
  undefined4 *puStack_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  int *piStack_38;
  undefined4 local_24;
  int local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 uStack_14;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_c = *unaff_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0062db46;
  *unaff_FS_OFFSET = &local_c;
  g_pUiResourceHead = (int *)0x0;
  if (param_2 == 0x7de) {
    piStack_38 = (int *)0x60;
    uStack_3c = 0x46fd56;
    iVar1 = AllocateWithFallbackHandler();
    local_4 = 0;
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piStack_38 = (int *)0x46fd6c;
      piVar2 = (int *)thunk_ConstructUiResourceEntryBase();
    }
    local_4 = 0xffffffff;
    if (g_pUiResourceHead == (int *)0x0) {
      uVar5 = 0;
      g_pUiResourceHead = piVar2;
    }
    else {
      uVar5 = *(undefined4 *)(DAT_006a13e8 + 8);
    }
    uStack_3c = 0x46fda6;
    g_pUiResourceContext = piVar2;
    piStack_38 = piVar2;
    thunk_PushUiResourcePoolNode();
    local_24 = 2000;
    local_20 = 2000;
    piStack_38 = (int *)0x1;
    uStack_3c = 0;
    puStack_44 = &local_24;
    uStack_40 = 0;
    piStack_48 = &local_1c;
    uStack_50 = 0;
    local_1c = 0;
    local_18 = 0;
    puStack_54 = (undefined1 *)0x46fdd6;
    uStack_4c = uVar5;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piStack_38 = (int *)0x0;
    uStack_3c = 1;
    piVar2[7] = 0x62617365;
    piVar2[0xf] = 0;
    uStack_40 = 0x46fdec;
    (**(code **)(iVar1 + 0xa4))();
    uStack_40 = 0;
    puStack_44 = (undefined4 *)0x0;
    piStack_48 = (int *)0x46fdf6;
    (**(code **)(iVar1 + 0xa8))();
    piStack_48 = (int *)0x90;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)g_pUiResourceContext + 0x4d) = 1;
    g_pUiResourceContext = (int *)0x0;
    uStack_4c = 0x46fe11;
    puStack_8 = (undefined1 *)AllocateWithFallbackHandler();
    uStack_14 = 1;
    if (puStack_8 == (undefined1 *)0x0) {
      piVar2 = (int *)0x0;
    }
    else {
      piStack_48 = (int *)0x46fe27;
      piVar2 = (int *)thunk_ConstructPictureResourceEntryBase();
    }
    uStack_14 = 0xffffffff;
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    uStack_4c = 0x46fe61;
    g_pUiResourceContext = piVar2;
    piStack_48 = piVar2;
    thunk_PushUiResourcePoolNode();
    piStack_48 = (int *)0x1;
    uStack_4c = 0;
    puStack_54 = &stack0xffffffd4;
    uStack_50 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piStack_48 = (int *)0x0;
    uStack_4c = 1;
    piVar2[7] = 0x6d61696e;
    piVar2[0xf] = 0;
    uStack_50 = 0x46fea5;
    (**(code **)(iVar1 + 0xa4))();
    uStack_50 = 0;
    puStack_54 = (undefined1 *)0x0;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    uStack_68 = 0x46fed4;
    piVar3 = (int *)CRect::CRect((CRect *)&uStack_3c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    local_20 = AllocateWithFallbackHandler();
    if (local_20 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructUiResourceEntryTypeB();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    ppuStack_6c = &puStack_44;
    uStack_68 = 0;
    puStack_44 = (undefined4 *)0x69;
    uStack_40 = 0x1a;
    uStack_4c = 0x10b;
    piStack_48 = (int *)0x5;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x746f7042;
    piVar2[0xf] = 0;
    uStack_68 = 0x46ffb1;
    (**(code **)(iVar1 + 0xa4))();
    uStack_68 = 0;
    ppuStack_6c = (undefined4 **)0x0;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 5;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_54,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    g_pUiResourceContext[0x21] = 0x20202020;
    g_pUiResourceContext = (int *)0x0;
    iVar1 = AllocateWithFallbackHandler();
    uStack_3c = 3;
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    uStack_3c = 0xffffffff;
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_54 = (undefined1 *)0xe;
    uStack_50 = 0x12;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x7472616e;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_90 = 0x4700e4;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffff9c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    piStack_48 = (int *)AllocateWithFallbackHandler();
    puStack_54 = (undefined1 *)0x4;
    if (piStack_48 == (int *)0x0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    puStack_54 = (undefined1 *)0xffffffff;
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    pppuStack_94 = &ppuStack_6c;
    iStack_90 = 0;
    ppuStack_6c = (undefined4 **)0xe;
    uStack_68 = 0x12;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x63697479;
    piVar2[0xf] = 0;
    iStack_90 = 0x4701cb;
    (**(code **)(iVar1 + 0xa4))();
    iStack_90 = 0;
    pppuStack_94 = (undefined4 ***)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    uStack_a8 = 0x4701fa;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffff84,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar1 = AllocateWithFallbackHandler();
    ppuStack_6c = (undefined4 **)0x5;
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    ppuStack_6c = (undefined4 **)0xffffffff;
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_ac = &stack0xffffff7c;
    uStack_a8 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x74726164;
    piVar2[0xf] = 0;
    uStack_a8 = 0x4702e1;
    (**(code **)(iVar1 + 0xa4))();
    uStack_a8 = 0;
    puStack_ac = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    uStack_c0 = 0x470310;
    piVar3 = (int *)CRect::CRect((CRect *)&pppuStack_94,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar1 = AllocateWithFallbackHandler();
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_c4 = &stack0xffffff64;
    uStack_c0 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x6469706c;
    piVar2[0xf] = 0;
    uStack_c0 = 0x4703f7;
    (**(code **)(iVar1 + 0xa4))();
    uStack_c0 = 0;
    puStack_c4 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_ac,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iStack_90 = AllocateWithFallbackHandler();
    if (iStack_90 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructUiResourceEntryTypeB();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x74627232;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 5;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_c4,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    g_pUiResourceContext[0x21] = 0x20202020;
    g_pUiResourceContext = (int *)0x0;
    iVar1 = AllocateWithFallbackHandler();
    puStack_ac = (undefined1 *)0x8;
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructUiTabCursorPictureEntry();
    }
    puStack_ac = (undefined1 *)0xffffffff;
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_c4 = (undefined1 *)0x19;
    uStack_c0 = 0x26;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x71756572;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffff2c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar1 = AllocateWithFallbackHandler();
    puStack_c4 = (undefined1 *)0x9;
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructUiResourceEntryTypeB();
    }
    puStack_c4 = (undefined1 *)0xffffffff;
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x746f6f6c;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 5;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffff14,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    g_pUiResourceContext[0x21] = 0x20202020;
    g_pUiResourceContext = (int *)0x0;
    iVar1 = AllocateWithFallbackHandler();
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructUiTabCursorPictureEntry();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x656e6420;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffff04,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar1 = AllocateWithFallbackHandler();
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructSelectableTextOptionEntryBase();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x73656173;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xd;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xfffffeec,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    thunk_SetUiResourceContextTagWord();
    thunk_BindUiResourceTextAndStyle();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar1 = AllocateWithFallbackHandler();
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructSelectableTextOptionEntryBase();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x74726561;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xd;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xfffffedc,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    thunk_SetUiResourceContextTagWord();
    iStack_160 = 0x470af0;
    thunk_BindUiResourceTextAndStyle();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar1 = AllocateWithFallbackHandler();
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00591e70();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x746f7461;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_160 = 0x470be2;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xfffffecc,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar1 = AllocateWithFallbackHandler();
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00591e70();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_164 = &stack0xfffffec4;
    iStack_160 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x66697368;
    piVar2[0xf] = 0;
    iStack_160 = 0x470cc9;
    (**(code **)(iVar1 + 0xa4))();
    iStack_160 = 0;
    puStack_164 = (undefined1 *)0x0;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_178 = 0x470cf8;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xfffffeb4,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    iVar1 = AllocateWithFallbackHandler();
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_17c = &stack0xfffffeac;
    iStack_178 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x6c656674;
    piVar2[0xf] = 0;
    iStack_178 = 0x470dd5;
    (**(code **)(iVar1 + 0xa4))();
    iStack_178 = 0;
    puStack_17c = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_190 = 0x470e04;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_164,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar1 = AllocateWithFallbackHandler();
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_194 = &stack0xfffffe94;
    iStack_190 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x72676874;
    piVar2[0xf] = 0;
    iStack_190 = 0x470eeb;
    (**(code **)(iVar1 + 0xa4))();
    iStack_190 = 0;
    puStack_194 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_1a8 = 0x470f1a;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_17c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iStack_160 = AllocateWithFallbackHandler();
    if (iStack_160 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00591e70();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_1ac = &stack0xfffffe7c;
    iStack_1a8 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x70726f64;
    piVar2[0xf] = 0;
    iStack_1a8 = 0x47100b;
    (**(code **)(iVar1 + 0xa4))();
    iStack_1a8 = 0;
    puStack_1ac = (undefined1 *)0x0;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_1c0 = 0x47103a;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_194,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    iStack_178 = AllocateWithFallbackHandler();
    if (iStack_178 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_1c4 = &stack0xfffffe64;
    iStack_1c0 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x6c656674;
    piVar2[0xf] = 0;
    iStack_1c0 = 0x471117;
    (**(code **)(iVar1 + 0xa4))();
    iStack_1c0 = 0;
    puStack_1c4 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_1d8 = 0x471146;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_1ac,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_190 = AllocateWithFallbackHandler();
    if (iStack_190 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_1dc = &stack0xfffffe4c;
    iStack_1d8 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x72676874;
    piVar2[0xf] = 0;
    iStack_1d8 = 0x47122d;
    (**(code **)(iVar1 + 0xa4))();
    iStack_1d8 = 0;
    puStack_1dc = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_1f0 = 0x47125c;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_1c4,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iStack_1a8 = AllocateWithFallbackHandler();
    if (iStack_1a8 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00591e70();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_1f4 = &stack0xfffffe34;
    iStack_1f0 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x67726169;
    piVar2[0xf] = 0;
    iStack_1f0 = 0x47134d;
    (**(code **)(iVar1 + 0xa4))();
    iStack_1f0 = 0;
    puStack_1f4 = (undefined1 *)0x0;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_208 = 0x47137c;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_1dc,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    iStack_1c0 = AllocateWithFallbackHandler();
    if (iStack_1c0 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_20c = &stack0xfffffe1c;
    iStack_208 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x6c656674;
    piVar2[0xf] = 0;
    iStack_208 = 0x471459;
    (**(code **)(iVar1 + 0xa4))();
    iStack_208 = 0;
    puStack_20c = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_220 = 0x471488;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_1f4,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_1d8 = AllocateWithFallbackHandler();
    if (iStack_1d8 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_224 = &stack0xfffffe04;
    iStack_220 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x72676874;
    piVar2[0xf] = 0;
    iStack_220 = 0x47156f;
    (**(code **)(iVar1 + 0xa4))();
    iStack_220 = 0;
    puStack_224 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_238 = 0x47159e;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_20c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iStack_1f0 = AllocateWithFallbackHandler();
    if (iStack_1f0 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00591e70();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_23c = &stack0xfffffdec;
    iStack_238 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x74696d62;
    piVar2[0xf] = 0;
    iStack_238 = 0x47168f;
    (**(code **)(iVar1 + 0xa4))();
    iStack_238 = 0;
    puStack_23c = (undefined1 *)0x0;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_250 = 0x4716be;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_224,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    iStack_208 = AllocateWithFallbackHandler();
    if (iStack_208 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_254 = &stack0xfffffdd4;
    iStack_250 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x6c656674;
    piVar2[0xf] = 0;
    iStack_250 = 0x47179b;
    (**(code **)(iVar1 + 0xa4))();
    iStack_250 = 0;
    puStack_254 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_268 = 0x4717ca;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_23c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_220 = AllocateWithFallbackHandler();
    if (iStack_220 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_26c = &stack0xfffffdbc;
    iStack_268 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x72676874;
    piVar2[0xf] = 0;
    iStack_268 = 0x4718b1;
    (**(code **)(iVar1 + 0xa4))();
    iStack_268 = 0;
    puStack_26c = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_280 = 0x4718e0;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_254,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iStack_238 = AllocateWithFallbackHandler();
    if (iStack_238 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00591e70();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_284 = &stack0xfffffda4;
    iStack_280 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x6c756d62;
    piVar2[0xf] = 0;
    iStack_280 = 0x4719d1;
    (**(code **)(iVar1 + 0xa4))();
    iStack_280 = 0;
    puStack_284 = (undefined1 *)0x0;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_298 = 0x471a00;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_26c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    iStack_250 = AllocateWithFallbackHandler();
    if (iStack_250 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_29c = &stack0xfffffd8c;
    iStack_298 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x6c656674;
    piVar2[0xf] = 0;
    iStack_298 = 0x471add;
    (**(code **)(iVar1 + 0xa4))();
    iStack_298 = 0;
    puStack_29c = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_2b0 = 0x471b0c;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_284,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_268 = AllocateWithFallbackHandler();
    if (iStack_268 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_2b4 = &stack0xfffffd74;
    iStack_2b0 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x72676874;
    piVar2[0xf] = 0;
    iStack_2b0 = 0x471bf3;
    (**(code **)(iVar1 + 0xa4))();
    iStack_2b0 = 0;
    puStack_2b4 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_2c8 = 0x471c22;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_29c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iStack_280 = AllocateWithFallbackHandler();
    if (iStack_280 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00591e70();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_2cc = &stack0xfffffd5c;
    iStack_2c8 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x6675726e;
    piVar2[0xf] = 0;
    iStack_2c8 = 0x471d13;
    (**(code **)(iVar1 + 0xa4))();
    iStack_2c8 = 0;
    puStack_2cc = (undefined1 *)0x0;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_2e0 = 0x471d42;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_2b4,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    iStack_298 = AllocateWithFallbackHandler();
    if (iStack_298 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_2e4 = &stack0xfffffd44;
    iStack_2e0 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x6c656674;
    piVar2[0xf] = 0;
    iStack_2e0 = 0x471e1f;
    (**(code **)(iVar1 + 0xa4))();
    iStack_2e0 = 0;
    puStack_2e4 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_2f8 = 0x471e4e;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_2cc,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_2b0 = AllocateWithFallbackHandler();
    if (iStack_2b0 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_2fc = &stack0xfffffd2c;
    iStack_2f8 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x72676874;
    piVar2[0xf] = 0;
    iStack_2f8 = 0x471f35;
    (**(code **)(iVar1 + 0xa4))();
    iStack_2f8 = 0;
    puStack_2fc = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_310 = 0x471f64;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_2e4,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iStack_2c8 = AllocateWithFallbackHandler();
    if (iStack_2c8 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00591e70();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_314 = &stack0xfffffd14;
    iStack_310 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x636f616c;
    piVar2[0xf] = 0;
    iStack_310 = 0x472055;
    (**(code **)(iVar1 + 0xa4))();
    iStack_310 = 0;
    puStack_314 = (undefined1 *)0x0;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_328 = 0x472084;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_2fc,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    iStack_2e0 = AllocateWithFallbackHandler();
    if (iStack_2e0 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_32c = &stack0xfffffcfc;
    iStack_328 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x6c656674;
    piVar2[0xf] = 0;
    iStack_328 = 0x472161;
    (**(code **)(iVar1 + 0xa4))();
    iStack_328 = 0;
    puStack_32c = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_340 = 0x472190;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_314,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_2f8 = AllocateWithFallbackHandler();
    if (iStack_2f8 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_344 = &stack0xfffffce4;
    iStack_340 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x72676874;
    piVar2[0xf] = 0;
    iStack_340 = 0x472277;
    (**(code **)(iVar1 + 0xa4))();
    iStack_340 = 0;
    puStack_344 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_358 = 0x4722a6;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_32c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iStack_310 = AllocateWithFallbackHandler();
    if (iStack_310 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00591e70();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_35c = &stack0xfffffccc;
    iStack_358 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x69726f6e;
    piVar2[0xf] = 0;
    iStack_358 = 0x472397;
    (**(code **)(iVar1 + 0xa4))();
    iStack_358 = 0;
    puStack_35c = (undefined1 *)0x0;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_370 = 0x4723c6;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_344,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    iStack_328 = AllocateWithFallbackHandler();
    if (iStack_328 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_374 = &stack0xfffffcb4;
    iStack_370 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x6c656674;
    piVar2[0xf] = 0;
    iStack_370 = 0x4724a3;
    (**(code **)(iVar1 + 0xa4))();
    iStack_370 = 0;
    puStack_374 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_388 = 0x4724d2;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_35c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_340 = AllocateWithFallbackHandler();
    if (iStack_340 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_38c = &stack0xfffffc9c;
    iStack_388 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x72676874;
    piVar2[0xf] = 0;
    iStack_388 = 0x4725b9;
    (**(code **)(iVar1 + 0xa4))();
    iStack_388 = 0;
    puStack_38c = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    iStack_3a0 = 0x4725e8;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_374,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iStack_358 = AllocateWithFallbackHandler();
    if (iStack_358 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00591e70();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_3a4 = &stack0xfffffc84;
    iStack_3a0 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x73746565;
    piVar2[0xf] = 0;
    iStack_3a0 = 0x4726d9;
    (**(code **)(iVar1 + 0xa4))();
    iStack_3a0 = 0;
    puStack_3a4 = (undefined1 *)0x0;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    uStack_3b8 = 0x472708;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_38c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    iStack_370 = AllocateWithFallbackHandler();
    if (iStack_370 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_3bc = &stack0xfffffc6c;
    uStack_3b8 = 0;
    iVar6 = 0xc;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x6c656674;
    piVar2[0xf] = 0;
    uStack_3b8 = 0x4727e5;
    (**(code **)(iVar1 + 0xa4))();
    uStack_3b8 = 0;
    puStack_3bc = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_3a4,0,0,0,0);
    uVar5 = 0xfb4;
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_388 = AllocateWithFallbackHandler();
    if (iStack_388 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00583b50();
    }
    if (g_pUiResourceHead == (int *)0x0) {
      iStack_388 = 0;
      g_pUiResourceHead = piVar2;
    }
    else {
      iStack_388 = *(undefined4 *)(DAT_006a13e8 + 8);
    }
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    iVar1 = 0xc;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iStack_388 = *piVar2;
    piVar2[7] = 0x72676874;
    piVar2[0xf] = 0;
    (**(code **)(iStack_388 + 0xa4))();
    (**(code **)(iVar6 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_3bc,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iStack_3a0 = AllocateWithFallbackHandler();
    if (iStack_3a0 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_FUN_00591e70();
    }
    if (g_pUiResourceHead == (int *)0x0) {
      iStack_3a0 = 0;
      g_pUiResourceHead = piVar2;
    }
    else {
      iStack_3a0 = *(undefined4 *)(DAT_006a13e8 + 8);
    }
    g_pUiResourceContext = piVar2;
    thunk_FUN_00426ec0();
    thunk_FUN_00427100();
    thunk_FUN_00427100();
    thunk_InitializeUiResourceEntryFrameAndParent(0);
    iStack_3a0 = *piVar2;
    piVar2[7] = 0x68617264;
    piVar2[0xf] = 0;
    (**(code **)(iStack_3a0 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x2a;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x6c656674,uVar4,0x55,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x2b;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x72676874,uVar4,0xd3,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x2c;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00591e70();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x636f7474,uVar4,0x145,0x76,0xe0,0x1e,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x2d;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x6c656674,uVar4,0x51,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x2e;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x72676874,uVar4,0xcf,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x2f;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00591e70();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x66616272,uVar4,0x145,0x95,0xe0,0x1e,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x30;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x6c656674,uVar4,0x51,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x31;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x72676874,uVar4,0xcf,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x32;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00591e70();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x636c6f74,uVar4,0x145,0xb4,0xe0,0x1e,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x33;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x6c656674,uVar4,0x51,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x34;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x72676874,uVar4,0xcf,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x35;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00591e70();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x6f696c20,uVar4,0x145,0xd3,0xe0,0x1e,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x36;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x6c656674,uVar4,0x51,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x37;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x72676874,uVar4,0xcf,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x38;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00591e70();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x6675656c,uVar4,0x145,0xf2,0xe0,0x1e,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x39;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x6c656674,uVar4,0x51,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x3a;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x72676874,uVar4,0xcf,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x3b;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00591e70();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x686f7273,uVar4,0x145,0x111,0xe0,0x1e,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x3c;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x6c656674,uVar4,0x51,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x3d;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x72676874,uVar4,0xcf,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x3e;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00591e70();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x676f6c64,uVar4,0x145,0x130,0xe0,0x1e,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x3f;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x6c656674,uVar4,0x51,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x40;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x72676874,uVar4,0xcf,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x41;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00591e70();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x67656d73,uVar4,0x145,0x14f,0xe0,0x1e,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x42;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x6c656674,uVar4,0x51,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x43;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_FUN_00583b50();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x70696374,0x72676874,uVar4,0xcf,8,0xb,0xc,1,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(10,0,0);
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x44;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_ConstructSelectableTextOptionEntryBase();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x73746174,0x7469744c,uVar4,0xa3,0x51,0x88,0x14,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(0xd,0,0);
    thunk_SetUiResourceContextTagWord(0);
    thunk_BindUiResourceTextAndStyle(0x1389,1,s_Transport_00694b14,0x3c76,0,0x12);
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x45;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_ConstructSelectableTextOptionEntryBase();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x73746174,0x74697452,uVar4,0x145,0x51,0x97,0x15,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_SetUiResourceLayoutValues(0xd,0,0);
    thunk_SetUiResourceContextTagWord(0);
    thunk_BindUiResourceTextAndStyle(0x1389,2,s_Ledger_00694b0c,0x3c76,0,0x12);
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    puStack_3bc = (undefined1 *)0x46;
    if (iVar1 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_ConstructUiCursorTextResourceEntry();
    }
    puStack_3bc = (undefined1 *)0xffffffff;
    thunk_RegisterUiResourceEntry(0x74657677,0x63757273,uVar4,0x191,4,0xdb,0x1e,0,1);
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    if (g_pUiResourceHead != (int *)0x0) {
      thunk_PropagateUiResourceContextRecursive();
    }
    piVar2 = g_pUiResourceHead;
    *unaff_FS_OFFSET = uVar5;
    return piVar2;
  }
  *unaff_FS_OFFSET = local_c;
  return (int *)0x0;
}

