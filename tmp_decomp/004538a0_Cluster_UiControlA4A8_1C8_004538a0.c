
int * Cluster_UiControlA4A8_1C8_004538a0(undefined4 param_1,short param_2)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  undefined4 uVar4;
  undefined4 *unaff_FS_OFFSET;
  undefined1 *puStack_1ac;
  undefined4 uStack_1a8;
  undefined1 *puStack_194;
  undefined4 uStack_190;
  undefined1 *puStack_17c;
  undefined4 uStack_178;
  undefined1 *puStack_164;
  int iStack_160;
  undefined1 *puStack_14c;
  int iStack_148;
  undefined1 *puStack_134;
  int iStack_130;
  undefined1 *puStack_11c;
  int iStack_118;
  undefined1 *puStack_104;
  int iStack_100;
  undefined1 *puStack_6c;
  undefined4 uStack_68;
  undefined1 *puStack_54;
  int iStack_50;
  char *pcStack_4c;
  int *piStack_48;
  undefined4 local_24;
  int *local_20;
  undefined4 local_1c;
  int local_18;
  undefined4 uStack_14;
  undefined4 local_c;
  int *piStack_8;
  undefined4 local_4;
  
  local_c = *unaff_FS_OFFSET;
  local_4 = 0xffffffff;
  piStack_8 = (int *)&LAB_0062c2e5;
  iVar1 = (int)param_2;
  *unaff_FS_OFFSET = &local_c;
  g_pUiResourceHead = (int *)0x0;
  if (iVar1 < 0x3c7) {
    if (iVar1 == 0x3c6) {
      iVar1 = thunk_AllocateUiResourceNode();
      local_4 = 0x25;
      if (iVar1 != 0) {
        thunk_ConstructUiWindowResourceEntryBase();
      }
      piStack_48 = (int *)0xaf;
      pcStack_4c = (char *)0x148;
      iStack_50 = 0x8a;
      puStack_54 = (undefined1 *)0xa0;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      piStack_48 = (int *)0x1;
      pcStack_4c = (char *)0x0;
      iStack_50 = 2;
      puStack_54 = (undefined1 *)0x8;
      thunk_SetUiResourceContextFlagsAndMetrics();
      piStack_48 = (int *)0x45416e;
      thunk_ApplyUiResourceColorTripletFromContext();
      thunk_ClearUiResourceContext();
      iVar1 = thunk_AllocateUiResourceNode();
      local_4 = 0x26;
      if (iVar1 != 0) {
        thunk_ConstructPictureResourceEntryBase();
      }
      piStack_48 = (int *)0xaf;
      pcStack_4c = (char *)0x14a;
      iStack_50 = 0;
      puStack_54 = (undefined1 *)0x0;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      piStack_48 = (int *)0xa;
      pcStack_4c = (char *)0x4541de;
      thunk_SetUiResourceLayoutValues();
      thunk_ApplyUiResourceLayoutFromContext();
      thunk_ClearUiResourceContext();
      iVar1 = thunk_AllocateUiResourceNode();
      local_4 = 0x27;
      if (iVar1 != 0) {
        thunk_ConstructUiTextResourceEntryBase();
      }
      piStack_48 = (int *)0x21;
      pcStack_4c = (char *)0x12d;
      iStack_50 = 0xe;
      puStack_54 = (undefined1 *)0xc;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      piStack_48 = (int *)0xd;
      pcStack_4c = (char *)0x45425a;
      thunk_SetUiResourceLayoutValues();
      thunk_SetUiResourceContextTagWord();
      piStack_48 = (int *)0x3;
      pcStack_4c = (char *)&DAT_006a13a0;
      iStack_50 = 0xffffffff;
      puStack_54 = (undefined1 *)0x514;
      thunk_BindUiResourceTextAndStyle();
      thunk_ClearUiResourceContext();
      thunk_PopUiResourcePoolNode();
      iVar1 = thunk_AllocateUiResourceNode();
      local_4 = 0x28;
      if (iVar1 != 0) {
        thunk_ConstructUiGoldLabelResourceEntry();
      }
      piStack_48 = (int *)0x55;
      pcStack_4c = (char *)0x122;
      iStack_50 = 0x34;
      puStack_54 = (undefined1 *)0x12;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      piStack_48 = (int *)0x5;
      pcStack_4c = (char *)0x4542fe;
      thunk_SetUiResourceLayoutValues();
      thunk_SetUiResourceContextStringCode();
      thunk_ClearUiResourceContext();
      thunk_PopUiResourcePoolNode();
      iVar1 = thunk_AllocateUiResourceNode();
      local_4 = 0x29;
      if (iVar1 != 0) {
        thunk_ConstructPictureScreenResourceEntry();
      }
      piStack_48 = (int *)0x18;
      pcStack_4c = (char *)0x3d;
      iStack_50 = 0x8b;
      puStack_54 = (undefined1 *)0xff;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      piStack_48 = (int *)0x22;
      pcStack_4c = (char *)0x45438b;
      thunk_SetUiResourceLayoutValues();
      thunk_ApplyUiResourceLayoutFromContext();
      thunk_ClearUiResourceContext();
    }
    else {
      if (iVar1 == 0x3b8) {
        iVar1 = thunk_AllocateUiResourceNode();
        local_4 = 0x60;
        if (iVar1 != 0) {
          thunk_ConstructUiResourceEntryBase();
        }
        piStack_48 = (int *)0x7d0;
        pcStack_4c = (char *)0x7d0;
        iStack_50 = 0;
        puStack_54 = (undefined1 *)0x0;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        thunk_ClearUiResourceContext();
        iVar1 = thunk_AllocateUiResourceNode();
        local_4 = 0x61;
        if (iVar1 != 0) {
          thunk_FUN_005969e0();
        }
        piStack_48 = (int *)0x1e0;
        pcStack_4c = (char *)0x280;
        iStack_50 = 0;
        puStack_54 = (undefined1 *)0x0;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        thunk_ReplaceUiResourceContextPairBuffer();
        piStack_48 = (int *)0xa;
        pcStack_4c = (char *)0x453dce;
        thunk_SetUiResourceLayoutValues();
        thunk_ApplyUiResourceLayoutFromContext();
        thunk_ClearUiResourceContext();
        iVar1 = thunk_AllocateUiResourceNode();
        local_4 = 0x62;
        if (iVar1 != 0) {
          thunk_ConstructUiResourceEntryTypeB();
        }
        piStack_48 = (int *)0x1e0;
        pcStack_4c = (char *)0x7b;
        iStack_50 = 0;
        puStack_54 = (undefined1 *)0x205;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        piStack_48 = (int *)0x5;
        pcStack_4c = (char *)0x453e4c;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextStringCode();
        thunk_ClearUiResourceContext();
        iVar1 = thunk_AllocateUiResourceNode();
        local_4 = 99;
        if (iVar1 != 0) {
          thunk_ConstructUiTabCursorPictureEntry();
        }
        piStack_48 = (int *)0x24;
        pcStack_4c = (char *)0x1a;
        iStack_50 = 8;
        puStack_54 = (undefined1 *)0x5b;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        piStack_48 = (int *)0xa;
        pcStack_4c = (char *)0x453ec5;
        thunk_SetUiResourceLayoutValues();
        thunk_ApplyUiResourceLayoutFromContext();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar1 = thunk_AllocateUiResourceNode();
        local_4 = 100;
        if (iVar1 != 0) {
          thunk_ConstructUiTabCursorPictureEntry();
        }
        piStack_48 = (int *)0x24;
        pcStack_4c = (char *)0x53;
        iStack_50 = 8;
        puStack_54 = (undefined1 *)0x4;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        piStack_48 = (int *)0xa;
        pcStack_4c = (char *)0x453f4b;
        thunk_SetUiResourceLayoutValues();
        thunk_ApplyUiResourceLayoutFromContext();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        thunk_PopUiResourcePoolNode();
        iVar1 = thunk_AllocateUiResourceNode();
        local_4 = 0x65;
        if (iVar1 != 0) {
          thunk_InitializeCitySiteView();
        }
        piStack_48 = (int *)0x1c0;
        pcStack_4c = (char *)0x200;
        iStack_50 = 0x1b;
        puStack_54 = (undefined1 *)0x5;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar1 = thunk_AllocateUiResourceNode();
        local_4 = 0x66;
        if (iVar1 != 0) {
          thunk_ConstructPictureScreenResourceEntry();
        }
        piStack_48 = (int *)0xb;
        pcStack_4c = (char *)0x13;
        iStack_50 = 10;
        puStack_54 = (undefined1 *)0xdc;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        piStack_48 = (int *)0xa;
        pcStack_4c = (char *)0x454052;
        thunk_SetUiResourceLayoutValues();
        thunk_ApplyUiResourceLayoutFromContext();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar1 = thunk_AllocateUiResourceNode();
        local_4 = 0x67;
        if (iVar1 != 0) {
          thunk_ConstructUiCursorTextResourceEntry();
        }
        piStack_48 = (int *)0x15;
        pcStack_4c = (char *)0x113;
        iStack_50 = 5;
        puStack_54 = (undefined1 *)0xf0;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        thunk_ClearUiResourceContext();
        goto LAB_004594f7;
      }
      if (iVar1 != 0x3b9) goto switchD_004543e3_caseD_5de;
      iVar1 = thunk_AllocateUiResourceNode();
      local_4 = 0x34;
      if (iVar1 != 0) {
        thunk_ConstructUiWindowResourceEntryBase();
      }
      piStack_48 = (int *)0xaf;
      pcStack_4c = (char *)0x148;
      iStack_50 = 0x8a;
      puStack_54 = (undefined1 *)0xa0;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      piStack_48 = (int *)0x1;
      pcStack_4c = (char *)0x0;
      iStack_50 = 2;
      puStack_54 = (undefined1 *)0x8;
      thunk_SetUiResourceContextFlagsAndMetrics();
      piStack_48 = (int *)0x453979;
      thunk_ApplyUiResourceColorTripletFromContext();
      thunk_ClearUiResourceContext();
      iVar1 = thunk_AllocateUiResourceNode();
      local_4 = 0x35;
      if (iVar1 != 0) {
        thunk_FUN_004d1800();
      }
      piStack_48 = (int *)0xaf;
      pcStack_4c = (char *)0x148;
      iStack_50 = 0;
      puStack_54 = (undefined1 *)0x0;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      piStack_48 = (int *)0xa;
      pcStack_4c = (char *)0x4539e9;
      thunk_SetUiResourceLayoutValues();
      thunk_ApplyUiResourceLayoutFromContext();
      thunk_ClearUiResourceContext();
      iVar1 = thunk_AllocateUiResourceNode();
      local_4 = 0x36;
      if (iVar1 != 0) {
        thunk_ConstructUiTextResourceEntryBase();
      }
      piStack_48 = (int *)0x1a;
      pcStack_4c = (char *)0xee;
      iStack_50 = 0x11;
      puStack_54 = (undefined1 *)0x2e;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      piStack_48 = (int *)0xd;
      pcStack_4c = (char *)0x453a65;
      thunk_SetUiResourceLayoutValues();
      thunk_SetUiResourceContextTagWord();
      piStack_48 = (int *)0x3;
      pcStack_4c = (char *)&DAT_006a13a0;
      iStack_50 = 0xffffffff;
      puStack_54 = (undefined1 *)0x514;
      thunk_BindUiResourceTextAndStyle();
      thunk_ClearUiResourceContext();
      thunk_PopUiResourcePoolNode();
      iVar1 = thunk_AllocateUiResourceNode();
      local_4 = 0x37;
      if (iVar1 != 0) {
        thunk_ConstructPictureScreenResourceEntry();
      }
      piStack_48 = (int *)0x18;
      pcStack_4c = (char *)0x3d;
      iStack_50 = 0x8e;
      puStack_54 = (undefined1 *)0xff;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      piStack_48 = (int *)0x22;
      pcStack_4c = (char *)0x453b0d;
      thunk_SetUiResourceLayoutValues();
      thunk_ApplyUiResourceLayoutFromContext();
      thunk_ClearUiResourceContext();
      thunk_PopUiResourcePoolNode();
      iVar1 = thunk_AllocateUiResourceNode();
      local_4 = 0x38;
      if (iVar1 != 0) {
        thunk_ConstructPictureScreenResourceEntry();
      }
      piStack_48 = (int *)0x17;
      pcStack_4c = (char *)0x3d;
      iStack_50 = 0x8e;
      puStack_54 = (undefined1 *)0xd;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      piStack_48 = (int *)0x22;
      pcStack_4c = (char *)0x453b97;
      thunk_SetUiResourceLayoutValues();
      thunk_ApplyUiResourceLayoutFromContext();
      thunk_ClearUiResourceContext();
      thunk_PopUiResourcePoolNode();
      iVar1 = thunk_AllocateUiResourceNode();
      local_4 = 0x39;
      if (iVar1 != 0) {
        thunk_ConstructUiTextResourceEntryBase();
      }
      piStack_48 = (int *)0xe;
      pcStack_4c = (char *)0xa8;
      iStack_50 = 0x5c;
      puStack_54 = (undefined1 *)0x11;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      piStack_48 = (int *)0xd;
      pcStack_4c = (char *)0x453c20;
      thunk_SetUiResourceLayoutValues();
      thunk_SetUiResourceContextTagWord();
      piStack_48 = (int *)0x3;
      pcStack_4c = (char *)&DAT_006a13a0;
      iStack_50 = 0xffffffff;
      puStack_54 = (undefined1 *)0x514;
      thunk_BindUiResourceTextAndStyle();
      thunk_ClearUiResourceContext();
      thunk_PopUiResourcePoolNode();
      iVar1 = thunk_AllocateUiResourceNode();
      local_4 = 0x3a;
      if (iVar1 != 0) {
        thunk_ConstructUiTextResourceEntryBase();
      }
      piStack_48 = (int *)0x1d;
      pcStack_4c = (char *)0x12b;
      iStack_50 = 0x3b;
      puStack_54 = (undefined1 *)0xe;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      piStack_48 = (int *)0xd;
      pcStack_4c = (char *)0x453cc2;
      thunk_SetUiResourceLayoutValues();
      thunk_SetUiResourceContextTagWord();
      piStack_48 = (int *)0x3;
      pcStack_4c = (char *)&DAT_006a13a0;
      iStack_50 = -1;
      puStack_54 = (undefined1 *)0x514;
      thunk_BindUiResourceTextAndStyle();
      thunk_ClearUiResourceContext();
    }
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    goto LAB_00459511;
  }
  if (0x5eb < iVar1) {
    if (iVar1 != 20000) {
switchD_004543e3_caseD_5de:
      *unaff_FS_OFFSET = local_c;
      return (int *)0x0;
    }
    iVar1 = AllocateWithFallbackHandler();
    local_4 = 0x19;
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructUiResourceEntryBase();
    }
    local_4 = 0xffffffff;
    if (g_pUiResourceHead == (int *)0x0) {
      uVar4 = 0;
      g_pUiResourceHead = piVar2;
    }
    else {
      uVar4 = *(undefined4 *)(DAT_006a13e8 + 8);
    }
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    piStack_48 = &local_24;
    iStack_50 = 0;
    local_1c = 2000;
    local_18 = 2000;
    local_24 = 0;
    local_20 = (int *)0x0;
    puStack_54 = (undefined1 *)0x458d76;
    pcStack_4c = (char *)uVar4;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x62617365;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    piStack_48 = (int *)0x458d97;
    (**(code **)(iVar1 + 0xa8))();
    piStack_48 = (int *)0x94;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)g_pUiResourceContext + 0x4d) = 1;
    g_pUiResourceContext = (int *)0x0;
    pcStack_4c = (char *)0x458db4;
    piVar2 = (int *)AllocateWithFallbackHandler();
    uStack_14 = 0x1a;
    piStack_8 = piVar2;
    if (piVar2 == (int *)0x0) {
      piVar2 = (int *)0x0;
    }
    else {
      piStack_48 = (int *)0x458dd0;
      thunk_ConstructPictureResourceEntryBase();
      *piVar2 = (int)&PTR_LAB_00643c78;
      *(undefined2 *)(piVar2 + 0x24) = 0;
    }
    uStack_14 = 0xffffffff;
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    pcStack_4c = (char *)0x458e11;
    g_pUiResourceContext = piVar2;
    piStack_48 = piVar2;
    thunk_PushUiResourcePoolNode();
    piStack_48 = (int *)0x1;
    pcStack_4c = (char *)0x0;
    puStack_54 = &stack0xffffffd4;
    iStack_50 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piStack_48 = (int *)0x0;
    pcStack_4c = (char *)0x1;
    piVar2[7] = 0x6d61696e;
    piVar2[0xf] = 0;
    iStack_50 = 0x458e57;
    (**(code **)(iVar1 + 0xa4))();
    iStack_50 = 0;
    puStack_54 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    FreeHeapBufferIfNotNull();
    local_18 = AllocateWithFallbackHandler();
    local_24 = 0x1b;
    if (local_18 == 0) {
      iVar1 = 0;
    }
    else {
      iVar1 = thunk_ZeroUiResourceContextStyleBytes();
    }
    piVar2[0x12] = iVar1;
    *(undefined4 *)(iVar1 + 4) = 0;
    *(undefined4 *)piVar2[0x12] = 0xffffff;
    piVar2 = g_pUiResourceContext;
    local_24 = 0xffffffff;
    g_pUiResourceContext[0x18] = 10;
    uStack_68 = 0x458ed3;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffffc4,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    piVar2 = (int *)AllocateWithFallbackHandler();
    local_20 = piVar2;
    if (piVar2 == (int *)0x0) {
      piVar2 = (int *)0x0;
    }
    else {
      thunk_FUN_0045ad20();
      thunk_FUN_0045b080();
      thunk_FUN_0045b080();
      uStack_68 = 0;
      *piVar2 = (int)&PTR_LAB_006406d8;
      puStack_6c = (undefined1 *)0x458f5b;
      piVar3 = (int *)thunk_FUN_0045b0a0();
      iVar1 = *piVar3;
      *(undefined1 *)(piVar2 + 0x28) = 0;
      piVar2[0x26] = iVar1;
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_6c = &stack0xffffffbc;
    uStack_68 = 0;
    pcStack_4c = (char *)0x7;
    piStack_48 = (int *)0x6;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x73616c65;
    piVar2[0xf] = 0;
    uStack_68 = 0x458fe8;
    (**(code **)(iVar1 + 0xa4))();
    uStack_68 = 0;
    puStack_6c = (undefined1 *)0x0;
    (**(code **)(iVar1 + 0xa8))();
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)g_pUiResourceContext + 0x4d) = 0;
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
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
    puStack_54 = (undefined1 *)0x61;
    iStack_50 = 0x25;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x73686f77;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffff9c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    piStack_48 = (int *)AllocateWithFallbackHandler();
    puStack_54 = (undefined1 *)0x1f;
    if (piStack_48 == (int *)0x0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructUiTabCursorPictureEntry();
    }
    puStack_54 = (undefined1 *)0xffffffff;
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_6c = (undefined1 *)0x61;
    uStack_68 = 0x25;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x71756974;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 10;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffff84,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    piVar2 = (int *)AllocateWithFallbackHandler();
    puStack_6c = (undefined1 *)0x20;
    if (piVar2 == (int *)0x0) {
      piVar2 = (int *)0x0;
    }
    else {
      thunk_FUN_0045ad20();
      puStack_6c = (undefined1 *)CONCAT31(puStack_6c._1_3_,0x21);
      thunk_FUN_0045b080();
      thunk_FUN_0045b080();
      *piVar2 = (int)&PTR_LAB_006406d8;
      piVar3 = (int *)thunk_FUN_0045b0a0();
      iVar1 = *piVar3;
      *(undefined1 *)(piVar2 + 0x28) = 0;
      piVar2[0x26] = iVar1;
    }
    puStack_6c = (undefined1 *)0xffffffff;
    piVar3 = piVar2;
    g_pUiResourceContext = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      thunk_GetUiLinkedListNodePayload();
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    thunk_PushUiLinkedListNodeWithPayload();
    thunk_SetUiResourcePairValues();
    thunk_SetUiResourcePairValues();
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x72657175;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x22;
    if (iVar1 != 0) {
      thunk_ConstructUiTextResourceEntryBase();
    }
    piStack_48 = (int *)0x17;
    pcStack_4c = (char *)0x8a;
    iStack_50 = 0x1be;
    puStack_54 = (undefined1 *)0x33;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x4593af;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x23;
    if (iVar1 != 0) {
      thunk_ConstructUiTextResourceEntryBase();
    }
    piStack_48 = (int *)0x17;
    pcStack_4c = (char *)0x8a;
    iStack_50 = 0x1bd;
    puStack_54 = (undefined1 *)0x1cb;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x459456;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x24;
    if (iVar1 != 0) {
      thunk_ConstructUiColorTextResourceEntry();
    }
    piStack_48 = (int *)0x25;
    pcStack_4c = (char *)0x177;
    iStack_50 = 6;
    puStack_54 = (undefined1 *)0x84;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    goto LAB_004594f7;
  }
  if (iVar1 == 0x5eb) {
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x72;
    if (iVar1 != 0) {
      thunk_ConstructUiResourceEntryBase();
    }
    piStack_48 = (int *)0x7d0;
    pcStack_4c = (char *)0x7d0;
    iStack_50 = 0;
    puStack_54 = (undefined1 *)0x0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x73;
    if (iVar1 != 0) {
      thunk_FUN_0045af80();
    }
    piStack_48 = (int *)0x1e0;
    pcStack_4c = (char *)0x280;
    iStack_50 = 0;
    puStack_54 = (undefined1 *)0x0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ReplaceUiResourceContextPairBuffer();
    piStack_48 = (int *)0xa;
    pcStack_4c = (char *)0x457ba5;
    thunk_SetUiResourceLayoutValues();
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x74;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x78;
    iStack_50 = 0xa5;
    puStack_54 = (undefined1 *)0x76;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x457c21;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x75;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x78;
    iStack_50 = 0xdb;
    puStack_54 = (undefined1 *)0x76;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x457cc2;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x76;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x78;
    iStack_50 = 0x111;
    puStack_54 = (undefined1 *)0x76;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x457d63;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x77;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x30;
    pcStack_4c = (char *)0x78;
    iStack_50 = 0x135;
    puStack_54 = (undefined1 *)0x76;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x457e04;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x78;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x78;
    iStack_50 = 0xa5;
    puStack_54 = (undefined1 *)0x1a0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x457ea8;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x79;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x78;
    iStack_50 = 0xdb;
    puStack_54 = (undefined1 *)0x1a0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x457f4c;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x7a;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x20;
    pcStack_4c = (char *)0x78;
    iStack_50 = 0x109;
    puStack_54 = (undefined1 *)0x1a0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x457ff0;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x7b;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x20;
    pcStack_4c = (char *)0x78;
    iStack_50 = 0x149;
    puStack_54 = (undefined1 *)0x1a0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x458094;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x7c;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x78;
    iStack_50 = 0x17f;
    puStack_54 = (undefined1 *)0x76;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x458135;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x7d;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x78;
    iStack_50 = 0x17d;
    puStack_54 = (undefined1 *)0x158;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x4581d9;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x7e;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x78;
    iStack_50 = 0x196;
    puStack_54 = (undefined1 *)0x158;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x45827d;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x7f;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x18;
    pcStack_4c = (char *)0x78;
    iStack_50 = 0x1b8;
    puStack_54 = (undefined1 *)0x15a;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x458321;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x80;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x49;
    iStack_50 = 0xa5;
    puStack_54 = (undefined1 *)0xe9;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x4583c5;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x81;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x49;
    iStack_50 = 0xdb;
    puStack_54 = (undefined1 *)0xe9;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x458469;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x82;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x49;
    iStack_50 = 0x111;
    puStack_54 = (undefined1 *)0xe9;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x45850d;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x83;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x49;
    iStack_50 = 0x145;
    puStack_54 = (undefined1 *)0xea;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x4585b1;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x84;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x49;
    iStack_50 = 0x17f;
    puStack_54 = (undefined1 *)0xe9;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x458655;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x85;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x49;
    iStack_50 = 0xa5;
    puStack_54 = (undefined1 *)0x213;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x4586f9;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x86;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x49;
    iStack_50 = 0xdb;
    puStack_54 = (undefined1 *)0x213;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x45879d;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x87;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x49;
    iStack_50 = 0x111;
    puStack_54 = (undefined1 *)0x213;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x458841;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x88;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x49;
    iStack_50 = 0x151;
    puStack_54 = (undefined1 *)0x213;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x4588e5;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x89;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x49;
    iStack_50 = 0x17d;
    puStack_54 = (undefined1 *)0x213;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x458989;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x8a;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x49;
    iStack_50 = 0x195;
    puStack_54 = (undefined1 *)0x214;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x458a2d;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x8b;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x18;
    pcStack_4c = (char *)0x49;
    iStack_50 = 0x1b8;
    puStack_54 = (undefined1 *)0x214;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x458ad1;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x8c;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x48;
    pcStack_4c = (char *)0x18c;
    iStack_50 = 0x2c;
    puStack_54 = (undefined1 *)0x82;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x458b75;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x8d;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x78;
    iStack_50 = 0x7f;
    puStack_54 = (undefined1 *)0x76;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x458c14;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Static_Text_00694354;
    iStack_50 = 3;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x8e;
    if (iVar1 != 0) {
      thunk_ConstructUiTabCursorPictureEntry();
    }
    piStack_48 = (int *)0x34;
    pcStack_4c = (char *)0x1f;
    iStack_50 = 0x26;
    puStack_54 = (undefined1 *)0x7;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xa;
    pcStack_4c = (char *)0x458cb2;
    thunk_SetUiResourceLayoutValues();
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    goto LAB_004594f7;
  }
  switch(iVar1) {
  case 0x5dc:
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x2a;
    if (iVar1 != 0) {
      thunk_ConstructUiResourceEntryBase();
    }
    piStack_48 = (int *)0x7d0;
    pcStack_4c = (char *)0x7d0;
    iStack_50 = 0;
    puStack_54 = (undefined1 *)0x0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x2b;
    if (iVar1 != 0) {
      thunk_FUN_00575860();
    }
    piStack_48 = (int *)0x1e0;
    pcStack_4c = (char *)0x280;
    iStack_50 = 0;
    puStack_54 = (undefined1 *)0x0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ReplaceUiResourceContextPairBuffer();
    piStack_48 = (int *)0xa;
    pcStack_4c = (char *)0x455dd8;
    thunk_SetUiResourceLayoutValues();
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x2c;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0x54;
    pcStack_4c = (char *)0x89;
    iStack_50 = 0x6f;
    puStack_54 = (undefined1 *)0x3d;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x455e54;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x2d;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0xab;
    pcStack_4c = (char *)0x8a;
    iStack_50 = 0xd1;
    puStack_54 = (undefined1 *)0xe;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x455ed6;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x2e;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0x8c;
    pcStack_4c = (char *)0x8f;
    iStack_50 = 0x102;
    puStack_54 = (undefined1 *)0x1ca;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x455f5b;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x2f;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0x4e;
    pcStack_4c = (char *)0xa4;
    iStack_50 = 0x71;
    puStack_54 = (undefined1 *)0x1c0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x455fda;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x30;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0x48;
    pcStack_4c = (char *)0x9c;
    iStack_50 = 0x18d;
    puStack_54 = (undefined1 *)0x1;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x456059;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x31;
    if (iVar1 != 0) {
      thunk_ConstructUiCursorTextResourceEntry();
    }
    piStack_48 = (int *)0x34;
    pcStack_4c = (char *)0x112;
    iStack_50 = 0x1a8;
    puStack_54 = (undefined1 *)0xb4;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x32;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0xc3;
    pcStack_4c = (char *)0xc3;
    iStack_50 = 0x66;
    puStack_54 = (undefined1 *)0xdd;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x45614e;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x33;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0x49;
    pcStack_4c = (char *)0x64;
    iStack_50 = 399;
    puStack_54 = (undefined1 *)0x21c;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x4561cd;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    break;
  case 0x5dd:
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x46;
    if (iVar1 != 0) {
      thunk_ConstructUiResourceEntryBase();
    }
    piStack_48 = (int *)0x7d0;
    pcStack_4c = (char *)0x7d0;
    iStack_50 = 0;
    puStack_54 = (undefined1 *)0x0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x47;
    if (iVar1 != 0) {
      thunk_ConstructTSetupRandomMapPictureBaseState();
    }
    piStack_48 = (int *)0x1e0;
    pcStack_4c = (char *)0x280;
    iStack_50 = 0;
    puStack_54 = (undefined1 *)0x0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ReplaceUiResourceContextPairBuffer();
    piStack_48 = (int *)0xa;
    pcStack_4c = (char *)0x45683f;
    thunk_SetUiResourceLayoutValues();
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x48;
    if (iVar1 != 0) {
      thunk_ConstructUiCursorTextResourceEntry();
    }
    piStack_48 = (int *)0x1b;
    pcStack_4c = (char *)0xee;
    iStack_50 = 0x16;
    puStack_54 = (undefined1 *)0x24;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x49;
    if (iVar1 != 0) {
      thunk_ConstructUiResourceEntryType4B0C0();
    }
    piStack_48 = (int *)0x1d2;
    pcStack_4c = (char *)0x159;
    iStack_50 = 4;
    puStack_54 = (undefined1 *)0x120;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x5;
    pcStack_4c = (char *)0x45692e;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextStringCode();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x4a;
    if (iVar1 != 0) {
      thunk_ConstructUiPlanetListResourceEntry();
    }
    piStack_48 = (int *)0xb4;
    pcStack_4c = (char *)0x144;
    iStack_50 = 10;
    puStack_54 = (undefined1 *)0xe;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x4b;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x90;
    iStack_50 = 0xe6;
    puStack_54 = (undefined1 *)0x42;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x456a1b;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = (char *)&DAT_006a13a0;
    iStack_50 = 0xffffffff;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x4c;
    if (iVar1 != 0) {
      thunk_FUN_0045b000();
    }
    piStack_48 = (int *)0x18;
    pcStack_4c = (char *)0x20;
    iStack_50 = 0xe1;
    puStack_54 = (undefined1 *)0x19;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x4d;
    if (iVar1 != 0) {
      thunk_ConstructUiNumericTextEntryBase();
    }
    piStack_48 = (int *)0x16;
    pcStack_4c = (char *)0x132;
    iStack_50 = 0xf9;
    puStack_54 = (undefined1 *)0x17;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x6;
    pcStack_4c = (char *)0x456b2d;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = (char *)&DAT_006a13a0;
    iStack_50 = 0xffffffff;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_UpdateUiResourceContextMetricWord27();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x4e;
    if (iVar1 != 0) {
      thunk_ConstructPictureScreenResourceEntry();
    }
    piStack_48 = (int *)0x1e;
    pcStack_4c = (char *)0x60;
    iStack_50 = 0x1a2;
    puStack_54 = (undefined1 *)0x80;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xa;
    pcStack_4c = (char *)0x456bdb;
    thunk_SetUiResourceLayoutValues();
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x4f;
    if (iVar1 != 0) {
      thunk_ConstructUiGoldLabelResourceEntry();
    }
    piStack_48 = (int *)0x54;
    pcStack_4c = (char *)0x12e;
    iStack_50 = 0x12a;
    puStack_54 = (undefined1 *)0x19;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x5;
    pcStack_4c = (char *)0x456c67;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextStringCode();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x50;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntry();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x12a;
    iStack_50 = 2;
    puStack_54 = (undefined1 *)0x2;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x456ce4;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Introductory_00694a58;
    iStack_50 = 0xc;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x51;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntry();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x12a;
    iStack_50 = 0x12;
    puStack_54 = (undefined1 *)0x2;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x456d87;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = &DAT_00694a50;
    iStack_50 = 0xd;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x52;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntry();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x12a;
    iStack_50 = 0x22;
    puStack_54 = (undefined1 *)0x2;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x456e2a;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Normal_00694a48;
    iStack_50 = 0xe;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x53;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntry();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x12a;
    iStack_50 = 0x32;
    puStack_54 = (undefined1 *)0x2;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x456ecd;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = &DAT_00694a40;
    iStack_50 = 0x11;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x54;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntry();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x12a;
    iStack_50 = 0x42;
    puStack_54 = (undefined1 *)0x2;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x456f70;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Nigh_On_Impossible_00694a28;
    iStack_50 = 0x12;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x55;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x12;
    pcStack_4c = (char *)0x9f;
    iStack_50 = 0x116;
    puStack_54 = (undefined1 *)0x1a;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x457022;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Difficulty_Setting_00694a10;
    iStack_50 = 0x13;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x56;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x3f;
    iStack_50 = 0x188;
    puStack_54 = (undefined1 *)0x1a;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x4570c3;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Names__00694a08;
    iStack_50 = 2;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x57;
    if (iVar1 != 0) {
      thunk_ConstructUiGoldLabelResourceEntry();
    }
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0xeb;
    iStack_50 = 0x186;
    puStack_54 = (undefined1 *)0x5b;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x5;
    pcStack_4c = (char *)0x457167;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextStringCode();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x58;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntry();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x73;
    iStack_50 = 2;
    puStack_54 = (undefined1 *)0x2;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x4571e1;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Historical_006949f8;
    iStack_50 = 7;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x59;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntry();
    }
    piStack_48 = (int *)0x10;
    pcStack_4c = (char *)0x73;
    iStack_50 = 2;
    puStack_54 = (undefined1 *)0x76;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x457281;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_Random_006949f0;
    iStack_50 = 8;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x5a;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0xe;
    pcStack_4c = (char *)0xe;
    iStack_50 = 0x119;
    puStack_54 = (undefined1 *)0x109;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x457340;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x5b;
    if (iVar1 != 0) {
      thunk_ConstructUiTextResourceEntryBase();
    }
    piStack_48 = (int *)0x29;
    pcStack_4c = (char *)0x41;
    iStack_50 = 0x42;
    puStack_54 = (undefined1 *)0xd9;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x4573bb;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = s_All_AutoGP_s_006949e0;
    iStack_50 = 1;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x5c;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0x4e;
    pcStack_4c = (char *)0x92;
    iStack_50 = 0x37;
    puStack_54 = (undefined1 *)0x2a;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x45745c;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x5d;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0xea;
    pcStack_4c = (char *)0x68;
    iStack_50 = 0x85;
    puStack_54 = (undefined1 *)0x2a;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x4574db;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x5e;
    if (iVar1 != 0) {
      thunk_ConstructPictureResourceEntryBase();
    }
    piStack_48 = (int *)0x5e;
    pcStack_4c = (char *)0x46;
    iStack_50 = 0x14d;
    puStack_54 = (undefined1 *)0xad;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xa;
    pcStack_4c = (char *)0x45755a;
    thunk_SetUiResourceLayoutValues();
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x5f;
    if (iVar1 != 0) {
      thunk_ConstructPictureResourceEntryType606E8();
    }
    piStack_48 = (int *)0x80;
    pcStack_4c = (char *)0x80;
    iStack_50 = 0x86;
    puStack_54 = (undefined1 *)0x93;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xa;
    pcStack_4c = (char *)0x4575ed;
    thunk_SetUiResourceLayoutValues();
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    break;
  default:
    goto switchD_004543e3_caseD_5de;
  case 0x5df:
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x68;
    if (iVar1 != 0) {
      thunk_ConstructUiResourceEntryBase();
    }
    piStack_48 = (int *)0x7d0;
    pcStack_4c = (char *)0x7d0;
    iStack_50 = 0;
    puStack_54 = (undefined1 *)0x0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x69;
    if (iVar1 != 0) {
      thunk_FUN_0045ae60();
    }
    piStack_48 = (int *)0x1e0;
    pcStack_4c = (char *)0x280;
    iStack_50 = 0;
    puStack_54 = (undefined1 *)0x0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ReplaceUiResourceContextPairBuffer();
    piStack_48 = (int *)0xa;
    pcStack_4c = (char *)0x4576e0;
    thunk_SetUiResourceLayoutValues();
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x6a;
    if (iVar1 != 0) {
      thunk_ConstructUiPlanetListResourceEntry();
    }
    piStack_48 = (int *)0xb4;
    pcStack_4c = (char *)0x144;
    iStack_50 = 0xe;
    puStack_54 = (undefined1 *)0x12e;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x6b;
    if (iVar1 != 0) {
      thunk_ConstructPictureScreenResourceEntry();
    }
    piStack_48 = (int *)0x1e;
    pcStack_4c = (char *)0x60;
    iStack_50 = 0x1a6;
    puStack_54 = (undefined1 *)0x1a0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xa;
    pcStack_4c = (char *)0x4577ce;
    thunk_SetUiResourceLayoutValues();
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x6c;
    if (iVar1 != 0) {
      thunk_ConstructUiColorTextResourceEntry();
    }
    piStack_48 = (int *)0xb9;
    pcStack_4c = (char *)0x136;
    iStack_50 = 0xe6;
    puStack_54 = (undefined1 *)0x135;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x6d;
    if (iVar1 != 0) {
      thunk_ConstructUiColorTextResourceEntry();
    }
    piStack_48 = (int *)0xde;
    pcStack_4c = (char *)0xe4;
    iStack_50 = 0xe6;
    puStack_54 = (undefined1 *)0x30;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x6e;
    if (iVar1 != 0) {
      thunk_FUN_0045aee0();
    }
    piStack_48 = (int *)0x6e;
    pcStack_4c = (char *)0xf4;
    iStack_50 = 0x3d;
    puStack_54 = (undefined1 *)0x27;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x6f;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntry();
    }
    piStack_48 = (int *)0xf0;
    pcStack_4c = (char *)0x25;
    iStack_50 = 0x3e;
    puStack_54 = (undefined1 *)0x0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x4579ad;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x70;
    if (iVar1 != 0) {
      thunk_ConstructUiCursorTextResourceEntry();
    }
    piStack_48 = (int *)0x1e;
    pcStack_4c = (char *)0xd6;
    iStack_50 = 0x11;
    puStack_54 = (undefined1 *)0x32;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x71;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0xf2;
    iStack_50 = 0xb0;
    puStack_54 = (undefined1 *)0x28;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x457a99;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = (char *)&DAT_006a13a0;
    iStack_50 = -1;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    break;
  case 0x5e0:
    iVar1 = AllocateWithFallbackHandler();
    local_4 = 0x15;
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructUiResourceEntryBase();
    }
    local_4 = 0xffffffff;
    if (g_pUiResourceHead == (int *)0x0) {
      uVar4 = 0;
      g_pUiResourceHead = piVar2;
    }
    else {
      uVar4 = *(undefined4 *)(DAT_006a13e8 + 8);
    }
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    piStack_48 = &local_24;
    iStack_50 = 0;
    local_1c = 2000;
    local_18 = 2000;
    local_24 = 0;
    local_20 = (int *)0x0;
    puStack_54 = (undefined1 *)0x455a3c;
    pcStack_4c = (char *)uVar4;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x62617365;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    piStack_48 = (int *)0x455a5d;
    (**(code **)(iVar1 + 0xa8))();
    piStack_48 = (int *)0x1fc;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)g_pUiResourceContext + 0x4d) = 1;
    g_pUiResourceContext = (int *)0x0;
    pcStack_4c = (char *)0x455a7a;
    piVar2 = (int *)AllocateWithFallbackHandler();
    uStack_14 = 0x16;
    piStack_8 = piVar2;
    if (piVar2 == (int *)0x0) {
      piVar2 = (int *)0x0;
    }
    else {
      piStack_48 = (int *)0x455a96;
      thunk_ConstructPictureResourceEntryType606E8();
      *piVar2 = (int)&PTR_LAB_00643ea8;
    }
    uStack_14 = 0xffffffff;
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    pcStack_4c = (char *)0x455ad0;
    g_pUiResourceContext = piVar2;
    piStack_48 = piVar2;
    thunk_PushUiResourcePoolNode();
    piStack_48 = (int *)0x1;
    pcStack_4c = (char *)0x0;
    puStack_54 = &stack0xffffffd4;
    iStack_50 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piStack_48 = (int *)0x0;
    pcStack_4c = (char *)0x1;
    piVar2[7] = 0x6d61696e;
    piVar2[0xf] = 0;
    iStack_50 = 0x455b16;
    (**(code **)(iVar1 + 0xa4))();
    iStack_50 = 0;
    puStack_54 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    FreeHeapBufferIfNotNull();
    local_18 = AllocateWithFallbackHandler();
    local_24 = 0x17;
    if (local_18 == 0) {
      iVar1 = 0;
    }
    else {
      iVar1 = thunk_ZeroUiResourceContextStyleBytes();
    }
    piVar2[0x12] = iVar1;
    *(undefined4 *)(iVar1 + 4) = 0;
    *(undefined4 *)piVar2[0x12] = 0xffffff;
    piVar2 = g_pUiResourceContext;
    local_24 = 0xffffffff;
    g_pUiResourceContext[0x18] = 10;
    uStack_68 = 0x455b92;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffffc4,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    local_20 = (int *)AllocateWithFallbackHandler();
    if (local_20 == (int *)0x0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructUiTextResourceEntryBase();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_6c = &stack0xffffffbc;
    uStack_68 = 0;
    pcStack_4c = (char *)0x1b;
    piStack_48 = (int *)0x44;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x6c61626c;
    piVar2[0xf] = 0;
    uStack_68 = 0x455c6d;
    (**(code **)(iVar1 + 0xa4))();
    uStack_68 = 0;
    puStack_6c = (undefined1 *)0x0;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xd;
    piStack_48 = (int *)0x455c9e;
    piVar3 = (int *)CRect::CRect((CRect *)&local_1c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = (char *)&DAT_006a13a0;
    iStack_50 = -1;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    goto LAB_00455cdb;
  case 0x5e2:
    iVar1 = AllocateWithFallbackHandler();
    local_4 = 0;
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructUiResourceEntryBase();
    }
    local_4 = 0xffffffff;
    if (g_pUiResourceHead == (int *)0x0) {
      uVar4 = 0;
      g_pUiResourceHead = piVar2;
    }
    else {
      uVar4 = *(undefined4 *)(DAT_006a13e8 + 8);
    }
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    piStack_48 = &local_1c;
    iStack_50 = 0;
    local_24 = 2000;
    local_20 = (int *)0x7d0;
    local_1c = 0;
    local_18 = 0;
    puStack_54 = (undefined1 *)0x45446f;
    pcStack_4c = (char *)uVar4;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x62617365;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    piStack_48 = (int *)0x454490;
    (**(code **)(iVar1 + 0xa8))();
    piStack_48 = (int *)0x94;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)g_pUiResourceContext + 0x4d) = 1;
    g_pUiResourceContext = (int *)0x0;
    pcStack_4c = (char *)0x4544ad;
    piVar2 = (int *)AllocateWithFallbackHandler();
    uStack_14 = 1;
    piStack_8 = piVar2;
    if (piVar2 == (int *)0x0) {
      piVar2 = (int *)0x0;
    }
    else {
      piStack_48 = (int *)0x4544c9;
      thunk_ConstructPictureResourceEntryType606E8();
      *piVar2 = (int)&PTR_LAB_006440d8;
    }
    uStack_14 = 0xffffffff;
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    pcStack_4c = (char *)0x454503;
    g_pUiResourceContext = piVar2;
    piStack_48 = piVar2;
    thunk_PushUiResourcePoolNode();
    piStack_48 = (int *)0x1;
    pcStack_4c = (char *)0x0;
    puStack_54 = &stack0xffffffd4;
    iStack_50 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piStack_48 = (int *)0x0;
    pcStack_4c = (char *)0x1;
    piVar2[7] = 0x6d61696e;
    piVar2[0xf] = 0;
    iStack_50 = 0x454549;
    (**(code **)(iVar1 + 0xa4))();
    iStack_50 = 0;
    puStack_54 = (undefined1 *)0x0;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    FreeHeapBufferIfNotNull();
    local_18 = AllocateWithFallbackHandler();
    local_24 = 2;
    if (local_18 == 0) {
      iVar1 = 0;
    }
    else {
      iVar1 = thunk_ZeroUiResourceContextStyleBytes();
    }
    piVar2[0x12] = iVar1;
    *(undefined4 *)(iVar1 + 4) = 0;
    *(undefined4 *)piVar2[0x12] = 0xffffff;
    piVar2 = g_pUiResourceContext;
    local_24 = 0xffffffff;
    g_pUiResourceContext[0x18] = 10;
    uStack_68 = 0x4545c4;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffffc4,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    local_20 = (int *)AllocateWithFallbackHandler();
    if (local_20 == (int *)0x0) {
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
    puStack_6c = &stack0xffffffbc;
    uStack_68 = 0;
    pcStack_4c = (char *)0x221;
    piStack_48 = (int *)0x1bc;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x6f6b6179;
    piVar2[0xf] = 0;
    uStack_68 = 0x45469e;
    (**(code **)(iVar1 + 0xa4))();
    uStack_68 = 0;
    puStack_6c = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0x22;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_54,0,0,0,0);
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
    piVar2[7] = 0x636e636c;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0x22;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_6c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_50 = AllocateWithFallbackHandler();
    if (iStack_50 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructUiTextResourceEntry_Vtbl0066cbc8();
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
    piVar2[7] = 0x74787430;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xd;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffff7c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    thunk_SetUiResourceContextTagWord();
    thunk_BindUiResourceTextAndStyle();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar1 = AllocateWithFallbackHandler();
    puStack_6c = (undefined1 *)0x6;
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructUiTextResourceEntry_Vtbl0066cbc8();
    }
    puStack_6c = (undefined1 *)0xffffffff;
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x74787431;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xd;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffff6c,0,0,0,0);
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
      piVar2 = (int *)thunk_ConstructUiTextResourceEntry_Vtbl0066cbc8();
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
    piVar2[7] = 0x74787432;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xd;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffff5c,0,0,0,0);
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
      piVar2 = (int *)thunk_ConstructUiTextResourceEntry_Vtbl0066cbc8();
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
    piVar2[7] = 0x74787433;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xd;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffff4c,0,0,0,0);
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
      piVar2 = (int *)thunk_ConstructUiResourceEntryType4B0C0();
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
    piVar2[7] = 0x70726f74;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 5;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffff3c,0,0,0,0);
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
      piVar2 = (int *)thunk_ConstructUiClickablePictureResourceEntry();
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
    piVar2[7] = 0x72616430;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xc;
    iStack_100 = 0x454ea0;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffff2c,0,0,0,0);
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
      piVar2 = (int *)thunk_ConstructUiClickablePictureResourceEntry();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_104 = &stack0xffffff24;
    iStack_100 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x72616431;
    piVar2[0xf] = 0;
    iStack_100 = 0x454f85;
    (**(code **)(iVar1 + 0xa4))();
    iStack_100 = 0;
    puStack_104 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xc;
    iStack_118 = 0x454fb8;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xffffff14,0,0,0,0);
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
      piVar2 = (int *)thunk_ConstructUiClickablePictureResourceEntry();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_11c = &stack0xffffff0c;
    iStack_118 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x72616432;
    piVar2[0xf] = 0;
    iStack_118 = 0x455099;
    (**(code **)(iVar1 + 0xa4))();
    iStack_118 = 0;
    puStack_11c = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xc;
    iStack_130 = 0x4550cb;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_104,0,0,0,0);
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
      piVar2 = (int *)thunk_ConstructUiClickablePictureResourceEntry();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_134 = &stack0xfffffef4;
    iStack_130 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x72616433;
    piVar2[0xf] = 0;
    iStack_130 = 0x4551b0;
    (**(code **)(iVar1 + 0xa4))();
    iStack_130 = 0;
    puStack_134 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xc;
    iStack_148 = 0x4551e2;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_11c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iStack_100 = AllocateWithFallbackHandler();
    if (iStack_100 == 0) {
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
    puStack_14c = &stack0xfffffedc;
    iStack_148 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x73657430;
    piVar2[0xf] = 0;
    iStack_148 = 0x4552d1;
    (**(code **)(iVar1 + 0xa4))();
    iStack_148 = 0;
    puStack_14c = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0x22;
    iStack_160 = 0x455303;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_134,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_118 = AllocateWithFallbackHandler();
    if (iStack_118 == 0) {
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
    puStack_164 = &stack0xfffffec4;
    iStack_160 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x73657431;
    piVar2[0xf] = 0;
    iStack_160 = 0x4553e8;
    (**(code **)(iVar1 + 0xa4))();
    iStack_160 = 0;
    puStack_164 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0x22;
    uStack_178 = 0x45541a;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_14c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_130 = AllocateWithFallbackHandler();
    if (iStack_130 == 0) {
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
    puStack_17c = &stack0xfffffeac;
    uStack_178 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x73657432;
    piVar2[0xf] = 0;
    uStack_178 = 0x4554ff;
    (**(code **)(iVar1 + 0xa4))();
    uStack_178 = 0;
    puStack_17c = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0x22;
    uStack_190 = 0x455531;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_164,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_148 = AllocateWithFallbackHandler();
    if (iStack_148 == 0) {
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
    puStack_194 = &stack0xfffffe94;
    uStack_190 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x73657433;
    piVar2[0xf] = 0;
    uStack_190 = 0x455616;
    (**(code **)(iVar1 + 0xa4))();
    uStack_190 = 0;
    puStack_194 = (undefined1 *)0x1;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0x22;
    uStack_1a8 = 0x455648;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_17c,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    (**(code **)(*g_pUiResourceContext + 0x1c8))();
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iStack_160 = AllocateWithFallbackHandler();
    if (iStack_160 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructUiTextResourceEntryBase();
    }
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_1ac = &stack0xfffffe7c;
    uStack_1a8 = 0;
    thunk_InitializeUiResourceEntryFrameAndParent();
    iVar1 = *piVar2;
    piVar2[7] = 0x7467616d;
    piVar2[0xf] = 0;
    uStack_1a8 = 0x45572d;
    (**(code **)(iVar1 + 0xa4))();
    uStack_1a8 = 0;
    puStack_1ac = (undefined1 *)0x0;
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 1;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 0xd;
    piVar3 = (int *)CRect::CRect((CRect *)&puStack_194,0,0,0,0);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    thunk_SetUiResourceContextTagWord();
    thunk_BindUiResourceTextAndStyle(0x514,0xf);
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    iVar1 = AllocateWithFallbackHandler();
    puStack_17c = (undefined1 *)0x13;
    if (iVar1 == 0) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = (int *)thunk_ConstructUiNumericTextEntryBase();
    }
    puStack_17c = (undefined1 *)0xffffffff;
    piVar3 = piVar2;
    if (g_pUiResourceHead != (int *)0x0) {
      piVar3 = g_pUiResourceHead;
    }
    g_pUiResourceHead = piVar3;
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_194 = (undefined1 *)0x121;
    uStack_190 = 0x16;
    thunk_InitializeUiResourceEntryFrameAndParent(0);
    iVar1 = *piVar2;
    piVar2[7] = 0x67616d65;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))();
    piVar2 = g_pUiResourceContext;
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)piVar2 + 0x4d) = 0;
    piVar2 = g_pUiResourceContext;
    g_pUiResourceContext[0x18] = 6;
    piVar3 = (int *)CRect::CRect((CRect *)&stack0xfffffe5c,3,3,3,3);
    piVar2[0x1a] = *piVar3;
    piVar2[0x1b] = piVar3[1];
    piVar2[0x1c] = piVar3[2];
    piVar2[0x1d] = piVar3[3];
    thunk_SetUiResourceContextTagWord(0);
    thunk_BindUiResourceTextAndStyle(0x514,0x10,s_Revenge_of_the_Patagonians_00694a68,0,0,0);
    piVar2 = g_pUiResourceContext;
    (**(code **)(*g_pUiResourceContext + 0xc))();
    *(undefined2 *)(piVar2 + 0x27) = 0xff;
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    piVar2 = (int *)AllocateWithFallbackHandler();
    if (piVar2 == (int *)0x0) {
      piVar2 = (int *)0x0;
    }
    else {
      thunk_ConstructUiColorTextResourceEntry();
      *piVar2 = (int)&PTR_LAB_0063eb00;
    }
    if (g_pUiResourceHead == (int *)0x0) {
      uVar4 = 0;
      g_pUiResourceHead = piVar2;
    }
    else {
      uVar4 = *(undefined4 *)(DAT_006a13e8 + 8);
    }
    g_pUiResourceContext = piVar2;
    thunk_PushUiResourcePoolNode();
    puStack_1ac = (undefined1 *)0x15;
    uStack_1a8 = 0x43;
    thunk_InitializeUiResourceEntryFrameAndParent(0,uVar4,&puStack_1ac,&stack0xfffffe5c,0);
    iVar1 = *piVar2;
    piVar2[7] = 0x6c61626c;
    piVar2[0xf] = 0;
    (**(code **)(iVar1 + 0xa4))();
    (**(code **)(iVar1 + 0xa8))(0,0);
    *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
    *(undefined1 *)((int)g_pUiResourceContext + 0x4d) = 0;
LAB_00455cdb:
    g_pUiResourceContext = (int *)0x0;
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    goto LAB_00459519;
  case 0x5e5:
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x3b;
    if (iVar1 != 0) {
      thunk_ConstructUiResourceEntryBase();
    }
    piStack_48 = (int *)0x7d0;
    pcStack_4c = (char *)0x7d0;
    iStack_50 = 0;
    puStack_54 = (undefined1 *)0x0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x3c;
    if (iVar1 != 0) {
      thunk_FUN_00575f30();
    }
    piStack_48 = (int *)0x1e0;
    pcStack_4c = (char *)0x280;
    iStack_50 = 0;
    puStack_54 = (undefined1 *)0x0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ReplaceUiResourceContextPairBuffer();
    piStack_48 = (int *)0xa;
    pcStack_4c = (char *)0x4562b3;
    thunk_SetUiResourceLayoutValues();
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x3d;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0x56;
    pcStack_4c = (char *)0x93;
    iStack_50 = 0x50;
    puStack_54 = (undefined1 *)0x1d0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x456332;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x3e;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0xab;
    pcStack_4c = (char *)0x8a;
    iStack_50 = 0xda;
    puStack_54 = (undefined1 *)0x1ba;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x4563b7;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x3f;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0xba;
    pcStack_4c = (char *)0x82;
    iStack_50 = 0x4f;
    puStack_54 = (undefined1 *)0xc;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x456436;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x40;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0x48;
    pcStack_4c = (char *)0x9c;
    iStack_50 = 0x196;
    puStack_54 = (undefined1 *)0x128;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x4564b8;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x41;
    if (iVar1 != 0) {
      thunk_ConstructUiCursorTextResourceEntry();
    }
    piStack_48 = (int *)0x21;
    pcStack_4c = (char *)0xe9;
    iStack_50 = 0x12;
    puStack_54 = (undefined1 *)0x22;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x42;
    if (iVar1 != 0) {
      thunk_ConstructSelectableTextOptionEntryBase();
    }
    piStack_48 = (int *)0x13;
    pcStack_4c = (char *)0xa5;
    iStack_50 = 0x17d;
    puStack_54 = (undefined1 *)0xf5;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0xd;
    pcStack_4c = (char *)0x4565a6;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    piStack_48 = (int *)0x0;
    pcStack_4c = (char *)&DAT_006a13a0;
    iStack_50 = 0xffffffff;
    puStack_54 = (undefined1 *)0x514;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x43;
    if (iVar1 != 0) {
      thunk_ConstructUiGoldLabelResourceEntry();
    }
    piStack_48 = (int *)0xaf;
    pcStack_4c = (char *)0x100;
    iStack_50 = 0x58;
    puStack_54 = (undefined1 *)0xa3;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x5;
    pcStack_4c = (char *)0x45664c;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextStringCode();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x44;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0x98;
    pcStack_4c = (char *)0xa0;
    iStack_50 = 0x11a;
    puStack_54 = (undefined1 *)0x1d;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x4566db;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar1 = thunk_AllocateUiResourceNode();
    local_4 = 0x45;
    if (iVar1 != 0) {
      thunk_ConstructUiCommandTagResourceEntryBase();
    }
    piStack_48 = (int *)0x35;
    pcStack_4c = (char *)0x21;
    iStack_50 = 0x100;
    puStack_54 = (undefined1 *)0x186;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    piStack_48 = (int *)0x14;
    pcStack_4c = (char *)0x456759;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
  }
LAB_004594f7:
  thunk_PopUiResourcePoolNode();
  thunk_PopUiResourcePoolNode();
LAB_00459511:
  thunk_PopUiResourcePoolNode();
LAB_00459519:
  if (g_pUiResourceHead != (int *)0x0) {
    thunk_PropagateUiResourceContextRecursive();
  }
  piVar2 = g_pUiResourceHead;
  *unaff_FS_OFFSET = local_c;
  return piVar2;
}

