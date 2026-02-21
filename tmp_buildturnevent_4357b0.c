
/* Setting prototype: int * BuildTurnEventDialogUiByCode(int nContextSlot, int nEventCode) */

int * __fastcall BuildTurnEventDialogUiByCode(int nContextSlot,int nEventCode)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  undefined4 uVar5;
  char *pcVar6;
  undefined4 *unaff_FS_OFFSET;
  short in_stack_00000008;
  int ***pppiStack_70;
  int iStack_6c;
  int iVar7;
  int *piStack_58;
  undefined1 *puStack_54;
  undefined4 uStack_50;
  int *piStack_4c;
  int **ppiStack_48;
  int iVar8;
  int *local_24;
  undefined4 local_20;
  int *local_1c;
  undefined4 local_18;
  int *local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_c = (int *)*unaff_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0062a8f6;
  *unaff_FS_OFFSET = &local_c;
  g_pUiResourceHead = (int *)0x0;
  if (in_stack_00000008 < 0x3bb) {
    if (in_stack_00000008 == 0x3ba) {
      iVar2 = thunk_AllocateUiResourceNode();
      local_4 = 0x8d;
      if (iVar2 == 0) {
        piStack_58 = (int *)0x0;
      }
      else {
        piStack_58 = (int *)thunk_ConstructUiWindowResourceEntryBase();
      }
      ppiStack_48 = (int **)0xb1;
      piStack_4c = (int *)0xfc;
      uStack_50 = 0x8a;
      puStack_54 = (undefined1 *)0xa0;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      ppiStack_48 = (int **)0x1;
      piStack_4c = (int *)0x0;
      uStack_50 = 2;
      puStack_54 = (undefined1 *)0x8;
      piStack_58 = (int *)0x43598d;
      thunk_SetUiResourceContextFlagsAndMetrics();
      ppiStack_48 = (int **)0x4359a3;
      thunk_ApplyUiResourceColorTripletFromContext();
      thunk_ClearUiResourceContext();
      iVar2 = thunk_AllocateUiResourceNode();
      local_4 = 0x8e;
      if (iVar2 == 0) {
        piStack_58 = (int *)0x0;
      }
      else {
        piStack_58 = (int *)thunk_ConstructPictureResourceEntryBase();
      }
      ppiStack_48 = (int **)0xb1;
      piStack_4c = (int *)0xfc;
      uStack_50 = 0;
      puStack_54 = (undefined1 *)0x0;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      ppiStack_48 = (int **)0xa;
      piStack_4c = (int *)0x435a13;
      thunk_SetUiResourceLayoutValues();
      thunk_ApplyUiResourceLayoutFromContext();
      thunk_ClearUiResourceContext();
      iVar2 = thunk_AllocateUiResourceNode();
      local_4 = 0x8f;
      if (iVar2 == 0) {
        piStack_58 = (int *)0x0;
      }
      else {
        piStack_58 = (int *)thunk_ConstructUiGoldLabelResourceEntry();
      }
      ppiStack_48 = (int **)0x14;
      piStack_4c = (int *)0xaf;
      uStack_50 = 0x6e;
      puStack_54 = (undefined1 *)0x27;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      ppiStack_48 = (int **)0x5;
      piStack_4c = (int *)0x435a8e;
      thunk_SetUiResourceLayoutValues();
      thunk_SetUiResourceContextStringCode();
      thunk_ClearUiResourceContext();
      iVar2 = thunk_AllocateUiResourceNode();
      local_4 = 0x90;
      if (iVar2 == 0) {
        piStack_58 = (int *)0x0;
      }
      else {
        piStack_58 = (int *)thunk_ConstructSelectableTextOptionEntry();
      }
      ppiStack_48 = (int **)0x10;
      piStack_4c = (int *)0x55;
      uStack_50 = 2;
      puStack_54 = (undefined1 *)0x2;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      ppiStack_48 = (int **)0xd;
      piStack_4c = (int *)0x435b08;
      thunk_SetUiResourceLayoutValues();
      thunk_SetUiResourceContextTagWord();
      ppiStack_48 = (int **)0x0;
      piStack_4c = &DAT_006a13a0;
      uStack_50 = 0xffffffff;
      puStack_54 = (undefined1 *)0x514;
      piStack_58 = (int *)0x435b2d;
      thunk_BindUiResourceTextAndStyle();
      thunk_ClearUiResourceContext();
      thunk_PopUiResourcePoolNode();
      iVar2 = thunk_AllocateUiResourceNode();
      local_4 = 0x91;
      if (iVar2 == 0) {
        piStack_58 = (int *)0x0;
      }
      else {
        piStack_58 = (int *)thunk_ConstructSelectableTextOptionEntry();
      }
      ppiStack_48 = (int **)0x10;
      piStack_4c = (int *)0x55;
      uStack_50 = 2;
      puStack_54 = (undefined1 *)0x58;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      ppiStack_48 = (int **)0xd;
      piStack_4c = (int *)0x435ba7;
      thunk_SetUiResourceLayoutValues();
      thunk_SetUiResourceContextTagWord();
      ppiStack_48 = (int **)0x0;
      piStack_4c = &DAT_006a13a0;
      uStack_50 = 0xffffffff;
      puStack_54 = (undefined1 *)0x514;
      piStack_58 = (int *)0x435bcc;
      thunk_BindUiResourceTextAndStyle();
      thunk_ClearUiResourceContext();
      thunk_PopUiResourcePoolNode();
      thunk_PopUiResourcePoolNode();
      iVar2 = thunk_AllocateUiResourceNode();
      local_4 = 0x92;
      if (iVar2 == 0) {
        piStack_58 = (int *)0x0;
      }
      else {
        piStack_58 = (int *)thunk_ConstructUiTextResourceEntryBase();
      }
      ppiStack_48 = (int **)0x37;
      piStack_4c = (int *)0xb6;
      uStack_50 = 0x16;
      puStack_54 = (undefined1 *)0x25;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      ppiStack_48 = (int **)0xd;
      piStack_4c = (int *)0x435c55;
      thunk_SetUiResourceLayoutValues();
      thunk_SetUiResourceContextTagWord();
      ppiStack_48 = (int **)0x3;
      piStack_4c = (int *)s_Pick_a_planet_00694530;
      uStack_50 = 3;
      puStack_54 = (undefined1 *)0x514;
      piStack_58 = (int *)0x435c7d;
      thunk_BindUiResourceTextAndStyle();
      thunk_ClearUiResourceContext();
      thunk_PopUiResourcePoolNode();
      iVar2 = thunk_AllocateUiResourceNode();
      local_4 = 0x93;
      if (iVar2 == 0) {
        piStack_58 = (int *)0x0;
      }
      else {
        piStack_58 = (int *)thunk_ConstructUiNumericTextEntryBase();
      }
      ppiStack_48 = (int **)0x17;
      piStack_4c = (int *)0xaf;
      uStack_50 = 0x4f;
      puStack_54 = (undefined1 *)0x28;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      ppiStack_48 = (int **)0x6;
      piStack_4c = (int *)0x435cfd;
      thunk_SetUiResourceLayoutValues();
      thunk_SetUiResourceContextTagWord();
      ppiStack_48 = (int **)0x3;
      piStack_4c = (int *)s_Skyron_00694528;
      uStack_50 = 1;
      puStack_54 = (undefined1 *)0x3b9;
      piStack_58 = (int *)0x435d24;
      thunk_BindUiResourceTextAndStyle();
      thunk_UpdateUiResourceContextMetricWord27();
      thunk_ClearUiResourceContext();
      thunk_PopUiResourcePoolNode();
      iVar2 = thunk_AllocateUiResourceNode();
      local_4 = 0x94;
      if (iVar2 == 0) {
        piStack_58 = (int *)0x0;
      }
      else {
        piStack_58 = (int *)thunk_ConstructPictureScreenResourceEntry();
      }
      ppiStack_48 = (int **)0x18;
      piStack_4c = (int *)0x3d;
      uStack_50 = 0x8a;
      puStack_54 = (undefined1 *)0x9e;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      ppiStack_48 = (int **)0x22;
      piStack_4c = (int *)0x435dae;
      thunk_SetUiResourceLayoutValues();
      thunk_ApplyUiResourceLayoutFromContext();
      thunk_ClearUiResourceContext();
      thunk_PopUiResourcePoolNode();
      iVar2 = thunk_AllocateUiResourceNode();
      local_4 = 0x95;
      if (iVar2 == 0) {
        piStack_58 = (int *)0x0;
      }
      else {
        piStack_58 = (int *)thunk_ConstructPictureScreenResourceEntry();
      }
      ppiStack_48 = (int **)0x18;
      piStack_4c = (int *)0x3d;
      uStack_50 = 0x8a;
      puStack_54 = (undefined1 *)0x21;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      ppiStack_48 = (int **)0x22;
      piStack_4c = (int *)0x435e36;
      thunk_SetUiResourceLayoutValues();
      thunk_ApplyUiResourceLayoutFromContext();
      thunk_ClearUiResourceContext();
LAB_0043a3fc:
      thunk_PopUiResourcePoolNode();
      thunk_PopUiResourcePoolNode();
    }
    else {
      if (in_stack_00000008 != 0x3b6) {
LAB_0043b084:
        *unaff_FS_OFFSET = local_c;
        return (int *)0x0;
      }
      iVar2 = thunk_AllocateUiResourceNode();
      local_4 = 0x37;
      if (iVar2 == 0) {
        piStack_58 = (int *)0x0;
      }
      else {
        piStack_58 = (int *)thunk_ConstructTurnEventWindowEntryStaticBackdrop();
      }
      ppiStack_48 = (int **)0x15e;
      piStack_4c = (int *)0x226;
      uStack_50 = 0x28;
      puStack_54 = (undefined1 *)0x28;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      ppiStack_48 = (int **)0x0;
      piStack_4c = (int *)0x0;
      uStack_50 = 3;
      puStack_54 = (undefined1 *)0x8;
      piStack_58 = (int *)0x435864;
      thunk_SetUiResourceContextFlagsAndMetrics();
      ppiStack_48 = (int **)0x435879;
      thunk_ApplyUiResourceColorTripletFromContext();
      thunk_ClearUiResourceContext();
      iVar2 = thunk_AllocateUiResourceNode();
      local_4 = 0x38;
      if (iVar2 == 0) {
        piStack_58 = (int *)0x0;
      }
      else {
        piStack_58 = (int *)thunk_ConstructPictureResourceEntryType606E8();
      }
      ppiStack_48 = (int **)0x15e;
      piStack_4c = (int *)0x226;
      uStack_50 = 0;
      puStack_54 = (undefined1 *)0x0;
      local_4 = 0xffffffff;
      thunk_RegisterUiResourceEntry();
      thunk_SetUiResourceStateFlags();
      ppiStack_48 = (int **)0x22;
      piStack_4c = (int *)0x4358ea;
      thunk_SetUiResourceLayoutValues();
      thunk_ApplyUiResourceLayoutFromContext();
      thunk_ClearUiResourceContext();
      thunk_PopUiResourcePoolNode();
    }
  }
  else {
    if (0x5de < in_stack_00000008) {
      if (in_stack_00000008 < 0x7e5) {
        if (in_stack_00000008 != 0x7e4) {
          if (in_stack_00000008 == 0x7d1) {
            iVar2 = AllocateWithFallbackHandler();
            local_4 = 1;
            if (iVar2 == 0) {
              piVar3 = (int *)0x0;
            }
            else {
              piVar3 = (int *)thunk_ConstructTurnOrderNavigationWindowEntryViewportAdaptive();
            }
            local_4 = 0xffffffff;
            if (g_pUiResourceHead == (int *)0x0) {
              pcVar6 = (char *)0x0;
              g_pUiResourceHead = piVar3;
            }
            else {
              pcVar6 = *(char **)(DAT_006a13e8 + 8);
            }
            g_pUiResourceContext = piVar3;
            thunk_PushUiResourcePoolNode();
            ppiStack_48 = &local_24;
            uStack_50 = 0;
            local_1c = (int *)0x258;
            local_18 = 400;
            local_24 = (int *)0x5;
            local_20 = 0x32;
            puStack_54 = (undefined1 *)0x436ab8;
            piStack_4c = (int *)pcVar6;
            thunk_InitializeUiResourceEntryFrameAndParent();
            iVar2 = *piVar3;
            piVar3[7] = 0x57494e44;
            piVar3[0xf] = 0;
            (**(code **)(iVar2 + 0xa4))();
            ppiStack_48 = (int **)0x436ad9;
            (**(code **)(iVar2 + 0xa8))();
            piVar3 = g_pUiResourceContext;
            *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
            *(undefined1 *)((int)piVar3 + 0x4d) = 1;
            piVar3 = g_pUiResourceContext;
            FreeHeapBufferIfNotNull();
            iVar2 = AllocateWithFallbackHandler();
            local_4 = 2;
            if (iVar2 == 0) {
              iVar2 = 0;
            }
            else {
              iVar2 = thunk_ZeroUiResourceContextStyleBytes();
            }
            piVar3[0x12] = iVar2;
            *(undefined4 *)(iVar2 + 4) = 0;
            local_4 = 0xffffffff;
            *(undefined4 *)piVar3[0x12] = 0xffffff;
            *(undefined1 *)(g_pUiResourceContext + 0x1c) = 0;
            *(undefined1 *)((int)g_pUiResourceContext + 0x6f) = 1;
            *(undefined1 *)((int)g_pUiResourceContext + 0x6e) = 1;
            *(undefined1 *)((int)g_pUiResourceContext + 0x6d) = 0;
            *(undefined1 *)(g_pUiResourceContext + 0x1b) = 0;
            *(undefined1 *)((int)g_pUiResourceContext + 0x71) = 1;
            *(undefined2 *)(g_pUiResourceContext + 0x27) = 8;
            *(undefined2 *)(g_pUiResourceContext + 0x18) = 2;
          }
          else {
            if (in_stack_00000008 != 0x7d2) goto LAB_0043b084;
            iVar2 = AllocateWithFallbackHandler();
            local_4 = 3;
            if (iVar2 == 0) {
              piVar3 = (int *)0x0;
            }
            else {
              piVar3 = (int *)thunk_ConstructTurnOrderNavigationWindowEntryViewportAdaptive();
            }
            local_4 = 0xffffffff;
            if (g_pUiResourceHead == (int *)0x0) {
              pcVar6 = (char *)0x0;
              g_pUiResourceHead = piVar3;
            }
            else {
              pcVar6 = *(char **)(DAT_006a13e8 + 8);
            }
            g_pUiResourceContext = piVar3;
            thunk_PushUiResourcePoolNode();
            ppiStack_48 = &local_24;
            uStack_50 = 0;
            local_1c = (int *)0x280;
            local_18 = 0x1e0;
            local_24 = (int *)0x0;
            local_20 = 0x28;
            puStack_54 = (undefined1 *)0x43697f;
            piStack_4c = (int *)pcVar6;
            thunk_InitializeUiResourceEntryFrameAndParent();
            iVar2 = *piVar3;
            piVar3[7] = 0x57494e44;
            piVar3[0xf] = 0;
            (**(code **)(iVar2 + 0xa4))();
            ppiStack_48 = (int **)0x4369a0;
            (**(code **)(iVar2 + 0xa8))();
            piVar3 = g_pUiResourceContext;
            *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
            *(undefined1 *)((int)piVar3 + 0x4d) = 1;
            piVar3 = g_pUiResourceContext;
            FreeHeapBufferIfNotNull();
            iVar2 = AllocateWithFallbackHandler();
            local_4 = 4;
            if (iVar2 == 0) {
              iVar2 = 0;
            }
            else {
              iVar2 = thunk_ZeroUiResourceContextStyleBytes();
            }
            piVar3[0x12] = iVar2;
            *(undefined4 *)(iVar2 + 4) = 0;
            local_4 = 0xffffffff;
            *(undefined4 *)piVar3[0x12] = 0xffffff;
            *(undefined1 *)(g_pUiResourceContext + 0x1c) = 0;
            *(undefined1 *)((int)g_pUiResourceContext + 0x6f) = 1;
            *(undefined1 *)((int)g_pUiResourceContext + 0x6e) = 1;
            *(undefined1 *)((int)g_pUiResourceContext + 0x6d) = 0;
            *(undefined1 *)(g_pUiResourceContext + 0x1b) = 0;
            *(undefined1 *)((int)g_pUiResourceContext + 0x71) = 1;
            *(undefined2 *)(g_pUiResourceContext + 0x27) = 8;
            *(undefined2 *)(g_pUiResourceContext + 0x18) = 4;
          }
          goto LAB_0043b1b6;
        }
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x4f;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiWindowResourceEntryBase();
        }
        ppiStack_48 = (int **)0x11a;
        piStack_4c = (int *)0x186;
        uStack_50 = 0x50;
        puStack_54 = (undefined1 *)0x64;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0x1;
        piStack_4c = (int *)0x0;
        uStack_50 = 2;
        puStack_54 = (undefined1 *)0x8;
        piStack_58 = (int *)0x436bcf;
        thunk_SetUiResourceContextFlagsAndMetrics();
        ppiStack_48 = (int **)0x436be5;
        thunk_ApplyUiResourceColorTripletFromContext();
        thunk_ClearUiResourceContext();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x50;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructPictureResourceEntryBase();
        }
        ppiStack_48 = (int **)0x11a;
        piStack_4c = (int *)0x186;
        uStack_50 = 0;
        puStack_54 = (undefined1 *)0x0;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xa;
        piStack_4c = (int *)0x436c55;
        thunk_SetUiResourceLayoutValues();
        thunk_ApplyUiResourceLayoutFromContext();
        thunk_ClearUiResourceContext();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x51;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiTextResourceEntryBase();
        }
        ppiStack_48 = (int **)0x5f;
        piStack_4c = (int *)0xaa;
        uStack_50 = 0x21;
        puStack_54 = (undefined1 *)0x6f;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x436cd1;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x3;
        piStack_4c = &DAT_006a13a0;
        uStack_50 = 0xffffffff;
        puStack_54 = (undefined1 *)0x514;
        piStack_58 = (int *)0x436cf9;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x52;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructPictureScreenResourceEntry();
        }
        ppiStack_48 = (int **)0x18;
        piStack_4c = (int *)0x3d;
        uStack_50 = 0xf8;
        puStack_54 = (undefined1 *)0x136;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0x22;
        piStack_4c = (int *)0x436d79;
        thunk_SetUiResourceLayoutValues();
        thunk_ApplyUiResourceLayoutFromContext();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x53;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructPictureScreenResourceEntry();
        }
        ppiStack_48 = (int **)0x18;
        piStack_4c = (int *)0x3d;
        uStack_50 = 0xf8;
        puStack_54 = (undefined1 *)0x11;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0x22;
        piStack_4c = (int *)0x436e01;
        thunk_SetUiResourceLayoutValues();
        thunk_ApplyUiResourceLayoutFromContext();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x54;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructPictureResourceEntryBase();
        }
        ppiStack_48 = (int **)0x7d;
        piStack_4c = (int *)0x54;
        uStack_50 = 0xc;
        puStack_54 = (undefined1 *)0x127;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xa;
        piStack_4c = (int *)0x436e8a;
        thunk_SetUiResourceLayoutValues();
        thunk_ApplyUiResourceLayoutFromContext();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x55;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiColorTextResourceEntry();
        }
        ppiStack_48 = (int **)0x54;
        piStack_4c = (int *)0x162;
        uStack_50 = 0xa0;
        puStack_54 = (undefined1 *)0x11;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        thunk_ClearUiResourceContext();
      }
      else if (in_stack_00000008 < 0xbbe) {
        if (in_stack_00000008 != 0xbbd) {
          if (in_stack_00000008 != 3000) goto LAB_0043b084;
          iVar2 = AllocateWithFallbackHandler();
          local_4 = 6;
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiWindowResourceEntryType572C0();
          }
          local_4 = 0xffffffff;
          if (g_pUiResourceHead == (int *)0x0) {
            uVar5 = 0;
            g_pUiResourceHead = piVar3;
          }
          else {
            uVar5 = *(undefined4 *)(DAT_006a13e8 + 8);
          }
          g_pUiResourceContext = piVar3;
          thunk_PushUiResourcePoolNode();
          ppiStack_48 = &local_24;
          uStack_50 = 0;
          local_1c = (int *)0x186;
          local_18 = 0x13b;
          local_24 = (int *)0x64;
          local_20 = 100;
          puStack_54 = (undefined1 *)0x436fc6;
          piStack_4c = (int *)uVar5;
          thunk_InitializeUiResourceEntryFrameAndParent();
          iVar2 = *piVar3;
          iVar8 = 1;
          piVar3[7] = 0x57494e44;
          piVar3[0xf] = 0;
          (**(code **)(iVar2 + 0xa4))();
          ppiStack_48 = (int **)0x436fe8;
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
          ppiStack_48 = (int **)0x437032;
          piVar3 = (int *)(*pcVar1)();
          ppiStack_48 = (int **)0x1;
          piStack_4c = (int *)0x43703b;
          (**(code **)(*piVar3 + 0x30))();
          piStack_4c = (int *)0x20202020;
          uStack_50 = 0x20202020;
          puStack_54 = (undefined1 *)0x0;
          piStack_58 = (int *)0x43704a;
          (*pcVar1)();
          piStack_58 = (int *)0x437051;
          thunk_SetUiColorDescriptorGoldTriplet();
          piStack_4c = (int *)0x98;
          g_pUiResourceContext = (int *)0x0;
          uStack_50 = 0x437061;
          local_c = (int *)AllocateWithFallbackHandler();
          local_18 = 7;
          if (local_c == (int *)0x0) {
            piVar3 = (int *)0x0;
          }
          else {
            piStack_4c = (int *)0x43707b;
            piVar3 = (int *)thunk_ConstructPictureResourceEntryType57080();
          }
          local_18 = 0xffffffff;
          piVar4 = piVar3;
          if (g_pUiResourceHead != (int *)0x0) {
            piVar4 = g_pUiResourceHead;
          }
          g_pUiResourceHead = piVar4;
          uStack_50 = 0x4370b1;
          g_pUiResourceContext = piVar3;
          piStack_4c = piVar3;
          thunk_PushUiResourcePoolNode();
          piStack_4c = (int *)0x1;
          uStack_50 = 0;
          piStack_58 = (int *)&stack0xffffffd0;
          puStack_54 = (undefined1 *)0x0;
          thunk_InitializeUiResourceEntryFrameAndParent();
          iVar2 = *piVar3;
          piStack_4c = (int *)0x0;
          uStack_50 = 1;
          piVar3[7] = 0x444c4f47;
          piVar3[0xf] = 0;
          puStack_54 = (undefined1 *)0x4370f7;
          (**(code **)(iVar2 + 0xa4))();
          puStack_54 = (undefined1 *)0x0;
          piStack_58 = (int *)0x0;
          (**(code **)(iVar2 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 10;
          iStack_6c = 0x437128;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffffc0,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          (**(code **)(*g_pUiResourceContext + 0x1c8))();
          g_pUiResourceContext = (int *)0x0;
          piVar3 = (int *)AllocateWithFallbackHandler();
          local_24 = piVar3;
          if (piVar3 == (int *)0x0) {
            piVar3 = (int *)0x0;
          }
          else {
            thunk_ConstructUiResourceEntryBase();
            *piVar3 = (int)&PTR_LAB_006417e0;
          }
          piVar4 = piVar3;
          if (g_pUiResourceHead != (int *)0x0) {
            piVar4 = g_pUiResourceHead;
          }
          g_pUiResourceHead = piVar4;
          g_pUiResourceContext = piVar3;
          thunk_PushUiResourcePoolNode();
          pppiStack_70 = &ppiStack_48;
          iStack_6c = 0;
          ppiStack_48 = (int **)0x16b;
          uStack_50 = 0x15;
          piStack_4c = (int *)0x92;
          thunk_InitializeUiResourceEntryFrameAndParent();
          iVar2 = *piVar3;
          piVar3[7] = 0x7377696e;
          piVar3[0xf] = 0;
          iStack_6c = 0x437206;
          (**(code **)(iVar2 + 0xa4))();
          iStack_6c = 0;
          pppiStack_70 = (int ***)0x0;
          (**(code **)(iVar2 + 0xa8))();
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)g_pUiResourceContext + 0x4d) = 1;
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          iVar2 = AllocateWithFallbackHandler();
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiStatusListTextEntry();
          }
          piVar4 = piVar3;
          if (g_pUiResourceHead != (int *)0x0) {
            piVar4 = g_pUiResourceHead;
          }
          g_pUiResourceHead = piVar4;
          g_pUiResourceContext = piVar3;
          thunk_PushUiResourcePoolNode();
          piStack_58 = (int *)0xf4;
          puStack_54 = (undefined1 *)0xf;
          iVar7 = 0xbb;
          thunk_InitializeUiResourceEntryFrameAndParent();
          piVar3[7] = 0x6e616d31;
          piVar3[0xf] = 0;
          (**(code **)(*piVar3 + 0xa4))();
          (**(code **)(iVar8 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 0xd;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff98,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          thunk_SetUiResourceContextTagWord();
          thunk_BindUiResourceTextAndStyle();
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          iVar2 = AllocateWithFallbackHandler();
          uStack_50 = 10;
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiStatusListTextEntry();
          }
          uStack_50 = 0xffffffff;
          piVar4 = piVar3;
          if (g_pUiResourceHead != (int *)0x0) {
            piVar4 = g_pUiResourceHead;
          }
          g_pUiResourceHead = piVar4;
          g_pUiResourceContext = piVar3;
          thunk_PushUiResourcePoolNode();
          pppiStack_70 = (int ***)0xf;
          iStack_6c = 0xcc;
          thunk_InitializeUiResourceEntryFrameAndParent();
          piVar3[7] = 0x6e616d32;
          piVar3[0xf] = 0;
          (**(code **)(*piVar3 + 0xa4))();
          (**(code **)((int)piStack_4c + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 0xd;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff88,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          puStack_54 = &stack0xffffff68;
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          thunk_SetUiResourceContextTagWord();
          thunk_BindUiResourceTextAndStyle();
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          puStack_54 = (undefined1 *)AllocateWithFallbackHandler();
          if (puStack_54 == (undefined1 *)0x0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiStatusListTextEntry();
          }
          if (g_pUiResourceHead == (int *)0x0) {
            puStack_54 = (undefined1 *)0x0;
            g_pUiResourceHead = piVar3;
          }
          else {
            puStack_54 = *(undefined1 **)(DAT_006a13e8 + 8);
          }
          g_pUiResourceContext = piVar3;
          thunk_PushUiResourcePoolNode();
          iVar8 = 0xdd;
          thunk_InitializeUiResourceEntryFrameAndParent();
          puStack_54 = (undefined1 *)*piVar3;
          piVar3[7] = 0x6e616d33;
          piVar3[0xf] = 0;
          (**(code **)((int)puStack_54 + 0xa4))();
          (**(code **)(iVar7 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 0xd;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff78,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          thunk_SetUiResourceContextTagWord();
          thunk_BindUiResourceTextAndStyle();
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          iVar2 = AllocateWithFallbackHandler();
          pppiStack_70 = (int ***)0xc;
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiStatusListTextEntry();
          }
          pppiStack_70 = (int ***)0xffffffff;
          piVar4 = piVar3;
          if (g_pUiResourceHead != (int *)0x0) {
            piVar4 = g_pUiResourceHead;
          }
          g_pUiResourceHead = piVar4;
          g_pUiResourceContext = piVar3;
          thunk_PushUiResourcePoolNode();
          iVar7 = 0xee;
          thunk_InitializeUiResourceEntryFrameAndParent();
          piVar3[7] = 0x6e616d34;
          piVar3[0xf] = 0;
          (**(code **)(*piVar3 + 0xa4))();
          (**(code **)(iStack_6c + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 0xd;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff68,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          thunk_SetUiResourceContextTagWord();
          thunk_BindUiResourceTextAndStyle();
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          iVar2 = AllocateWithFallbackHandler();
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiStatusListTextEntry();
          }
          piVar4 = piVar3;
          if (g_pUiResourceHead != (int *)0x0) {
            piVar4 = g_pUiResourceHead;
          }
          g_pUiResourceHead = piVar4;
          g_pUiResourceContext = piVar3;
          thunk_PushUiResourcePoolNode();
          thunk_InitializeUiResourceEntryFrameAndParent();
          piVar3[7] = 0x6e616d35;
          piVar3[0xf] = 0;
          (**(code **)(*piVar3 + 0xa4))();
          (**(code **)(iVar8 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 0xd;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff58,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          thunk_SetUiResourceContextTagWord();
          thunk_BindUiResourceTextAndStyle();
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          iVar2 = AllocateWithFallbackHandler();
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiStatusListTextEntry();
          }
          piVar4 = piVar3;
          if (g_pUiResourceHead != (int *)0x0) {
            piVar4 = g_pUiResourceHead;
          }
          g_pUiResourceHead = piVar4;
          g_pUiResourceContext = piVar3;
          thunk_PushUiResourcePoolNode();
          thunk_InitializeUiResourceEntryFrameAndParent();
          piVar3[7] = 0x70726576;
          piVar3[0xf] = 0;
          (**(code **)(*piVar3 + 0xa4))();
          (**(code **)(iVar7 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 0xd;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff48,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          thunk_SetUiResourceContextTagWord();
          thunk_BindUiResourceTextAndStyle();
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          iVar2 = AllocateWithFallbackHandler();
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiStatusListTextEntry();
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
          piVar3[7] = 0x6e657874;
          piVar3[0xf] = 0;
          (**(code **)(iVar2 + 0xa4))();
          (**(code **)(iVar2 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 0xd;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff38,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          thunk_SetUiResourceContextTagWord();
          thunk_BindUiResourceTextAndStyle();
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          iVar2 = AllocateWithFallbackHandler();
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiStatusListTextEntry();
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
          piVar3[7] = 0x6d6f7265;
          piVar3[0xf] = 0;
          (**(code **)(iVar2 + 0xa4))();
          (**(code **)(iVar2 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 0xd;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff28,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          thunk_SetUiResourceContextTagWord();
          thunk_BindUiResourceTextAndStyle();
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          iVar2 = AllocateWithFallbackHandler();
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiTextResourceEntryBase();
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
          piVar3[7] = 0x7469746c;
          piVar3[0xf] = 0;
          (**(code **)(iVar2 + 0xa4))();
          (**(code **)(iVar2 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 0xd;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff18,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          thunk_SetUiResourceContextTagWord();
          thunk_BindUiResourceTextAndStyle(0x5e5,0xffffffff);
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          iVar2 = AllocateWithFallbackHandler();
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiStatusListTextEntry();
          }
          piVar4 = piVar3;
          if (g_pUiResourceHead != (int *)0x0) {
            piVar4 = g_pUiResourceHead;
          }
          g_pUiResourceHead = piVar4;
          g_pUiResourceContext = piVar3;
          thunk_PushUiResourcePoolNode();
          thunk_InitializeUiResourceEntryFrameAndParent(0);
          iVar2 = *piVar3;
          piVar3[7] = 0x746f676c;
          piVar3[0xf] = 0;
          (**(code **)(iVar2 + 0xa4))();
          (**(code **)(iVar2 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 0xd;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff08,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          thunk_SetUiResourceContextTagWord(0x943c1c);
          thunk_BindUiResourceTextAndStyle(0x3e9,0x19,s_Show_Topics_0069443c,3,4,9);
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          iVar2 = AllocateWithFallbackHandler();
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructPictureResourceEntryBase();
          }
          if (g_pUiResourceHead == (int *)0x0) {
            uVar5 = 0;
            g_pUiResourceHead = piVar3;
          }
          else {
            uVar5 = *(undefined4 *)(DAT_006a13e8 + 8);
          }
          g_pUiResourceContext = piVar3;
          thunk_PushUiResourcePoolNode();
          thunk_InitializeUiResourceEntryFrameAndParent(0,uVar5,&stack0xffffff00,&stack0xffffff08,0)
          ;
          iVar2 = *piVar3;
          piVar3[7] = 0x636f6174;
          piVar3[0xf] = 0;
          (**(code **)(iVar2 + 0xa4))();
          (**(code **)(iVar2 + 0xa8))(0,0);
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 10;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xfffffef8,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          (**(code **)(*g_pUiResourceContext + 0x1c8))(0x251c,0);
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          iVar2 = AllocateWithFallbackHandler(0x94);
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiTextResourceEntryBase();
          }
          if (g_pUiResourceHead == (int *)0x0) {
            uVar5 = 0;
            g_pUiResourceHead = piVar3;
          }
          else {
            uVar5 = *(undefined4 *)(DAT_006a13e8 + 8);
          }
          g_pUiResourceContext = piVar3;
          thunk_PushUiResourcePoolNode(piVar3);
          thunk_InitializeUiResourceEntryFrameAndParent
                    (0,uVar5,&stack0xfffffee8,&stack0xfffffef0,0,0,1);
          iVar2 = *piVar3;
          piVar3[7] = 0x7375626a;
          piVar3[0xf] = 0;
          (**(code **)(iVar2 + 0xa4))(1,0);
          (**(code **)(iVar2 + 0xa8))(0,0);
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 0xd;
          ppiStack_48 = (int **)0x43801f;
          piVar4 = (int *)CRect::CRect((CRect *)&local_1c,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = &DAT_006a13a0;
          uStack_50 = 0xffffffff;
          puStack_54 = (undefined1 *)0x5e5;
          piStack_58 = (int *)0x438059;
          thunk_BindUiResourceTextAndStyle();
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          thunk_PopUiResourcePoolNode();
          thunk_PopUiResourcePoolNode();
          goto LAB_0043bc2b;
        }
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x39;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_FUN_00504d40();
        }
        ppiStack_48 = (int **)0x12c;
        piStack_4c = (int *)0x186;
        uStack_50 = 100;
        puStack_54 = (undefined1 *)0x64;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0x1;
        piStack_4c = (int *)0x1;
        uStack_50 = 8000;
        puStack_54 = (undefined1 *)0x80;
        piStack_58 = (int *)0x4380fe;
        thunk_SetUiResourceContextFlagsAndMetrics();
        ppiStack_48 = (int **)0x438113;
        thunk_ApplyUiResourceColorTripletFromContext();
        thunk_FUN_00426f80();
        thunk_ClearUiResourceContext();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x3a;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_FUN_0043d770();
        }
        ppiStack_48 = (int **)0x12c;
        piStack_4c = (int *)0x186;
        uStack_50 = 0;
        puStack_54 = (undefined1 *)0x0;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xa;
        piStack_4c = (int *)0x438188;
        thunk_SetUiResourceLayoutValues();
        thunk_ApplyUiResourceLayoutFromContext();
        thunk_ClearUiResourceContext();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x3b;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiColorTextResourceEntry();
        }
        ppiStack_48 = (int **)0x39;
        piStack_4c = (int *)0x175;
        uStack_50 = 0x5b;
        puStack_54 = (undefined1 *)0x9;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x3c;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiTextResourceEntryBase();
        }
        ppiStack_48 = (int **)0x2d;
        piStack_4c = (int *)0xdb;
        uStack_50 = 0xb;
        puStack_54 = (undefined1 *)0x55;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x438271;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x0;
        piStack_4c = &DAT_006a13a0;
        uStack_50 = 0xffffffff;
        puStack_54 = (undefined1 *)0x5e5;
        piStack_58 = (int *)0x438295;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x3d;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
        }
        ppiStack_48 = (int **)0xf;
        piStack_4c = (int *)0xb4;
        uStack_50 = 0xb2;
        puStack_54 = (undefined1 *)0xe;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x438313;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x3;
        piStack_4c = (int *)s_About_Civilians_00694514;
        uStack_50 = 0xf;
        puStack_54 = (undefined1 *)0x3e9;
        piStack_58 = (int *)0x43833f;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x3e;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
        }
        ppiStack_48 = (int **)0xf;
        piStack_4c = (int *)0xb4;
        uStack_50 = 0xc3;
        puStack_54 = (undefined1 *)0xe;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x4383bd;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x3;
        piStack_4c = (int *)s_Giving_Orders_00694504;
        uStack_50 = 0x11;
        puStack_54 = (undefined1 *)0x3e9;
        piStack_58 = (int *)0x4383e9;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x3f;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
        }
        ppiStack_48 = (int **)0xf;
        piStack_4c = (int *)0xb4;
        uStack_50 = 0xd4;
        puStack_54 = (undefined1 *)0xe;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x438467;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x3;
        piStack_4c = (int *)s_Displayed_Information_006944e8;
        uStack_50 = 0x12;
        puStack_54 = (undefined1 *)0x3e9;
        piStack_58 = (int *)0x438493;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x40;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
        }
        ppiStack_48 = (int **)0xf;
        piStack_4c = (int *)0xb4;
        uStack_50 = 0xe5;
        puStack_54 = (undefined1 *)0xe;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x438511;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x3;
        piStack_4c = (int *)s_Tip_1__Using_the_toolbar_to_cont_006944b4;
        uStack_50 = 0x13;
        puStack_54 = (undefined1 *)0x3e9;
        piStack_58 = (int *)0x43853e;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x41;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
        }
        ppiStack_48 = (int **)0xf;
        piStack_4c = (int *)0xb4;
        uStack_50 = 0xf6;
        puStack_54 = (undefined1 *)0xe;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x4385bc;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x3;
        piStack_4c = (int *)s_Tip_2__Having_a_nice_day_with_lo_00694484;
        uStack_50 = 0xe;
        puStack_54 = (undefined1 *)0x3e9;
        piStack_58 = (int *)0x4385e9;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x42;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
        }
        ppiStack_48 = (int **)0xf;
        piStack_4c = (int *)0xb4;
        uStack_50 = 0x107;
        puStack_54 = (undefined1 *)0xe;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x438667;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x3;
        piStack_4c = (int *)s_topic_6_00694430;
        uStack_50 = 0x1a;
        puStack_54 = (undefined1 *)0x3e9;
        piStack_58 = (int *)0x438694;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x43;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
        }
        ppiStack_48 = (int **)0xf;
        piStack_4c = (int *)0xb4;
        uStack_50 = 0xb2;
        puStack_54 = (undefined1 *)0xc6;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x438715;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x3;
        piStack_4c = (int *)s_About_Civilians_00694514;
        uStack_50 = 0xf;
        puStack_54 = (undefined1 *)0x3e9;
        piStack_58 = (int *)0x438741;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x44;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
        }
        ppiStack_48 = (int **)0xf;
        piStack_4c = (int *)0xb4;
        uStack_50 = 0xc3;
        puStack_54 = (undefined1 *)0xc6;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x4387c2;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x3;
        piStack_4c = (int *)s_Giving_Orders_00694504;
        uStack_50 = 0x11;
        puStack_54 = (undefined1 *)0x3e9;
        piStack_58 = (int *)0x4387ee;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x45;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
        }
        ppiStack_48 = (int **)0xf;
        piStack_4c = (int *)0xb4;
        uStack_50 = 0xd4;
        puStack_54 = (undefined1 *)0xc6;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x43886f;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x3;
        piStack_4c = (int *)s_Displayed_Information_006944e8;
        uStack_50 = 0x12;
        puStack_54 = (undefined1 *)0x3e9;
        piStack_58 = (int *)0x43889b;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x46;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
        }
        ppiStack_48 = (int **)0xf;
        piStack_4c = (int *)0xb4;
        uStack_50 = 0xe5;
        puStack_54 = (undefined1 *)0xc6;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x43891c;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x3;
        piStack_4c = (int *)s_Tip_1__Using_the_toolbar_to_cont_006944b4;
        uStack_50 = 0x13;
        puStack_54 = (undefined1 *)0x3e9;
        piStack_58 = (int *)0x438949;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x47;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
        }
        ppiStack_48 = (int **)0xf;
        piStack_4c = (int *)0xb4;
        uStack_50 = 0xf6;
        puStack_54 = (undefined1 *)0xc6;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x4389ca;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x3;
        piStack_4c = (int *)s_Tip_2__Having_a_nice_day_with_lo_00694484;
        uStack_50 = 0xe;
        puStack_54 = (undefined1 *)0x3e9;
        piStack_58 = (int *)0x4389f7;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x48;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
        }
        ppiStack_48 = (int **)0xf;
        piStack_4c = (int *)0xb4;
        uStack_50 = 0x107;
        puStack_54 = (undefined1 *)0xc6;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x438a78;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x3;
        piStack_4c = (int *)s_topic_6_00694430;
        uStack_50 = 0x1a;
        puStack_54 = (undefined1 *)0x3e9;
        piStack_58 = (int *)0x438aa5;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x49;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_FUN_00505ae0();
        }
        ppiStack_48 = (int **)0x40;
        piStack_4c = (int *)0x40;
        uStack_50 = 0xc;
        puStack_54 = (undefined1 *)0xb;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x4a;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_FUN_00505ae0();
        }
        ppiStack_48 = (int **)0x40;
        piStack_4c = (int *)0x40;
        uStack_50 = 0xc;
        puStack_54 = (undefined1 *)0x13b;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        thunk_ClearUiResourceContext();
        thunk_PopUiResourcePoolNode();
        iVar2 = thunk_AllocateUiResourceNode();
        local_4 = 0x4b;
        if (iVar2 == 0) {
          piStack_58 = (int *)0x0;
        }
        else {
          piStack_58 = (int *)thunk_ConstructUiTextResourceEntryBase();
        }
        ppiStack_48 = (int **)0x14;
        piStack_4c = (int *)0xdb;
        uStack_50 = 0x39;
        puStack_54 = (undefined1 *)0x55;
        local_4 = 0xffffffff;
        thunk_RegisterUiResourceEntry();
        thunk_SetUiResourceStateFlags();
        ppiStack_48 = (int **)0xd;
        piStack_4c = (int *)0x438bf4;
        thunk_SetUiResourceLayoutValues();
        thunk_SetUiResourceContextTagWord();
        ppiStack_48 = (int **)0x0;
        piStack_4c = &DAT_006a13a0;
        uStack_50 = 0xffffffff;
        puStack_54 = (undefined1 *)0x5e5;
        piStack_58 = (int *)0x438c18;
        thunk_BindUiResourceTextAndStyle();
        thunk_ClearUiResourceContext();
      }
      else {
        if (0x102c < in_stack_00000008) {
          if (in_stack_00000008 < 0x1050) {
            if (in_stack_00000008 == 0x104f) {
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x96;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiResourceEntryBase();
              }
              ppiStack_48 = (int **)0x7d0;
              piStack_4c = (int *)0x7d0;
              uStack_50 = 0;
              puStack_54 = (undefined1 *)0x0;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              thunk_ClearUiResourceContext();
              piVar3 = (int *)thunk_AllocateUiResourceNode();
              local_4 = 0x97;
              if (piVar3 == (int *)0x0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = ConstructTurnEventMainPictureEntry_104F(piVar3);
              }
              ppiStack_48 = (int **)0x1e0;
              piStack_4c = (int *)0x280;
              uStack_50 = 0;
              puStack_54 = (undefined1 *)0x0;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              ppiStack_48 = (int **)0xa;
              piStack_4c = (int *)0x43af72;
              thunk_SetUiResourceLayoutValues();
              thunk_ApplyUiResourceLayoutFromContext();
              thunk_ClearUiResourceContext();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x98;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiColorTextResourceEntry();
              }
              ppiStack_48 = (int **)0x1ac;
              piStack_4c = (int *)0x101;
              uStack_50 = 0x13;
              puStack_54 = (undefined1 *)0x24;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x99;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiColorTextResourceEntry();
              }
              ppiStack_48 = (int **)0x1ac;
              piStack_4c = (int *)0x122;
              uStack_50 = 0x13;
              puStack_54 = (undefined1 *)0x146;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              thunk_ClearUiResourceContext();
            }
            else {
              if (in_stack_00000008 != 0x1036) goto LAB_0043b084;
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x78;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiResourceEntryBase();
              }
              ppiStack_48 = (int **)0x1e0;
              piStack_4c = (int *)0x280;
              uStack_50 = 0;
              puStack_54 = (undefined1 *)0x0;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              thunk_ClearUiResourceContext();
              piVar3 = (int *)thunk_AllocateUiResourceNode();
              local_4 = 0x79;
              if (piVar3 == (int *)0x0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = ConstructTurnEventMainPictureEntry_1036(piVar3);
              }
              ppiStack_48 = (int **)0x1e0;
              piStack_4c = (int *)0x280;
              uStack_50 = 0;
              puStack_54 = (undefined1 *)0x0;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              ppiStack_48 = (int **)0xa;
              piStack_4c = (int *)0x43a4fd;
              thunk_SetUiResourceLayoutValues();
              thunk_ApplyUiResourceLayoutFromContext();
              thunk_ClearUiResourceContext();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x7a;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_FUN_00571c20();
              }
              ppiStack_48 = (int **)0x5b;
              piStack_4c = (int *)0x66;
              uStack_50 = 0x127;
              puStack_54 = (undefined1 *)0x36;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              ppiStack_48 = (int **)0xa;
              piStack_4c = (int *)0x43a57a;
              thunk_SetUiResourceLayoutValues();
              thunk_ApplyUiResourceLayoutFromContext();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x7b;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_FUN_00571c20();
              }
              ppiStack_48 = (int **)0x5b;
              piStack_4c = (int *)0x66;
              uStack_50 = 0x127;
              puStack_54 = (undefined1 *)0xc2;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              ppiStack_48 = (int **)0xa;
              piStack_4c = (int *)0x43a607;
              thunk_SetUiResourceLayoutValues();
              thunk_ApplyUiResourceLayoutFromContext();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x7c;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_FUN_0043d6f0();
              }
              ppiStack_48 = (int **)0xa0;
              piStack_4c = (int *)0xa0;
              uStack_50 = 0x9c;
              puStack_54 = (undefined1 *)0x186;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              ppiStack_48 = (int **)0xa;
              piStack_4c = (int *)0x43a69a;
              thunk_SetUiResourceLayoutValues();
              thunk_ApplyUiResourceLayoutFromContext();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x7d;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_FUN_0043d610();
              }
              ppiStack_48 = (int **)0x5b;
              piStack_4c = (int *)0x66;
              uStack_50 = 0x5c;
              puStack_54 = (undefined1 *)0x36;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              ppiStack_48 = (int **)0x14;
              piStack_4c = (int *)0x43a721;
              thunk_SetUiResourceLayoutValues();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x7e;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_FUN_0043d610();
              }
              ppiStack_48 = (int **)0x5b;
              piStack_4c = (int *)0x66;
              uStack_50 = 0x5c;
              puStack_54 = (undefined1 *)0xc2;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              ppiStack_48 = (int **)0x14;
              piStack_4c = (int *)0x43a79e;
              thunk_SetUiResourceLayoutValues();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x7f;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiResourceEntryTypeB();
              }
              ppiStack_48 = (int **)0x2e;
              piStack_4c = (int *)0x28;
              uStack_50 = 0x24;
              puStack_54 = (undefined1 *)0x25a;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              ppiStack_48 = (int **)0x5;
              piStack_4c = (int *)0x43a81a;
              thunk_SetUiResourceLayoutValues();
              thunk_SetUiResourceContextStringCode();
              thunk_ClearUiResourceContext();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x80;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiTabCursorPictureEntry();
              }
              ppiStack_48 = (int **)0x26;
              piStack_4c = (int *)0x16;
              uStack_50 = 3;
              puStack_54 = (undefined1 *)0x6;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              ppiStack_48 = (int **)0xa;
              piStack_4c = (int *)0x43a893;
              thunk_SetUiResourceLayoutValues();
              thunk_ApplyUiResourceLayoutFromContext();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x81;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiColorTextResourceEntry();
              }
              ppiStack_48 = (int **)0x2f;
              piStack_4c = (int *)0x60;
              uStack_50 = 0xc1;
              puStack_54 = (undefined1 *)0xc5;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x82;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiColorTextResourceEntry();
              }
              ppiStack_48 = (int **)0x2f;
              piStack_4c = (int *)0x60;
              uStack_50 = 0xc1;
              puStack_54 = (undefined1 *)0x39;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x83;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiColorTextResourceEntry();
              }
              ppiStack_48 = (int **)0x2f;
              piStack_4c = (int *)0x60;
              uStack_50 = 0x18c;
              puStack_54 = (undefined1 *)0x39;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x84;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiColorTextResourceEntry();
              }
              ppiStack_48 = (int **)0x2f;
              piStack_4c = (int *)0x60;
              uStack_50 = 0x18c;
              puStack_54 = (undefined1 *)0xc5;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x85;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiColorTextResourceEntry();
              }
              ppiStack_48 = (int **)0x2f;
              piStack_4c = (int *)0x60;
              uStack_50 = 0x142;
              puStack_54 = (undefined1 *)0x1a7;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x86;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiGoldLabelResourceEntry();
              }
              ppiStack_48 = (int **)0x14;
              piStack_4c = (int *)0xc3;
              uStack_50 = 0x1ad;
              puStack_54 = (undefined1 *)0x172;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              ppiStack_48 = (int **)0x5;
              piStack_4c = (int *)0x43ab58;
              thunk_SetUiResourceLayoutValues();
              thunk_SetUiResourceContextStringCode();
              thunk_ClearUiResourceContext();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x87;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructSelectableTextOptionEntry();
              }
              ppiStack_48 = (int **)0x10;
              piStack_4c = (int *)0x5f;
              uStack_50 = 2;
              puStack_54 = (undefined1 *)0x2;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              ppiStack_48 = (int **)0xd;
              piStack_4c = (int *)0x43abd2;
              thunk_SetUiResourceLayoutValues();
              thunk_SetUiResourceContextTagWord();
              ppiStack_48 = (int **)0x0;
              piStack_4c = &DAT_006a13a0;
              uStack_50 = 0xffffffff;
              puStack_54 = (undefined1 *)0x514;
              piStack_58 = (int *)0x43abfb;
              thunk_BindUiResourceTextAndStyle();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x88;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructSelectableTextOptionEntry();
              }
              ppiStack_48 = (int **)0x10;
              piStack_4c = (int *)0x5f;
              uStack_50 = 2;
              puStack_54 = (undefined1 *)0x62;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              ppiStack_48 = (int **)0xd;
              piStack_4c = (int *)0x43ac75;
              thunk_SetUiResourceLayoutValues();
              thunk_SetUiResourceContextTagWord();
              ppiStack_48 = (int **)0x0;
              piStack_4c = &DAT_006a13a0;
              uStack_50 = 0xffffffff;
              puStack_54 = (undefined1 *)0x514;
              piStack_58 = (int *)0x43ac9e;
              thunk_BindUiResourceTextAndStyle();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x89;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiColorTextResourceEntry();
              }
              ppiStack_48 = (int **)0x2f;
              piStack_4c = (int *)0xc3;
              uStack_50 = 0x17c;
              puStack_54 = (undefined1 *)0x172;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x8a;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiResourceEntryTypeB();
              }
              ppiStack_48 = (int **)0x5b;
              piStack_4c = (int *)0x40;
              uStack_50 = 6;
              puStack_54 = (undefined1 *)0x3;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              ppiStack_48 = (int **)0x5;
              piStack_4c = (int *)0x43ad96;
              thunk_SetUiResourceLayoutValues();
              thunk_SetUiResourceContextStringCode();
              thunk_ClearUiResourceContext();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x8b;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiTabCursorPictureEntry();
              }
              ppiStack_48 = (int **)0x33;
              piStack_4c = (int *)0x1f;
              uStack_50 = 0x20;
              puStack_54 = (undefined1 *)0x5;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              ppiStack_48 = (int **)0xa;
              piStack_4c = (int *)0x43ae0f;
              thunk_SetUiResourceLayoutValues();
              thunk_ApplyUiResourceLayoutFromContext();
              thunk_ClearUiResourceContext();
              thunk_PopUiResourcePoolNode();
              thunk_PopUiResourcePoolNode();
              iVar2 = thunk_AllocateUiResourceNode();
              local_4 = 0x8c;
              if (iVar2 == 0) {
                piStack_58 = (int *)0x0;
              }
              else {
                piStack_58 = (int *)thunk_ConstructUiCursorTextResourceEntry();
              }
              ppiStack_48 = (int **)0x1e;
              piStack_4c = (int *)0xc9;
              uStack_50 = 5;
              puStack_54 = (undefined1 *)0x182;
              local_4 = 0xffffffff;
              thunk_RegisterUiResourceEntry();
              thunk_SetUiResourceStateFlags();
              thunk_ClearUiResourceContext();
            }
          }
          else if (in_stack_00000008 == 0x10cc) {
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x56;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructUiResourceEntryBase();
            }
            ppiStack_48 = (int **)0x7d0;
            piStack_4c = (int *)0x7d0;
            uStack_50 = 0;
            puStack_54 = (undefined1 *)0x0;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            thunk_ClearUiResourceContext();
            piVar3 = (int *)thunk_AllocateUiResourceNode();
            local_4 = 0x57;
            if (piVar3 == (int *)0x0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = ConstructTurnEventMainPictureEntry_10CC(piVar3);
            }
            ppiStack_48 = (int **)0x1e0;
            piStack_4c = (int *)0x280;
            uStack_50 = 0;
            puStack_54 = (undefined1 *)0x0;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43b407;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x58;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructUiResourceEntryTypeB();
            }
            ppiStack_48 = (int **)0x5b;
            piStack_4c = (int *)0x40;
            uStack_50 = 6;
            puStack_54 = (undefined1 *)0x3;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0x5;
            piStack_4c = (int *)0x43b480;
            thunk_SetUiResourceLayoutValues();
            thunk_SetUiResourceContextStringCode();
            thunk_ClearUiResourceContext();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x59;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructUiTabCursorPictureEntry();
            }
            ppiStack_48 = (int **)0x33;
            piStack_4c = (int *)0x1f;
            uStack_50 = 0x20;
            puStack_54 = (undefined1 *)0x5;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43b4f9;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
            thunk_PopUiResourcePoolNode();
            thunk_PopUiResourcePoolNode();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x5a;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructUiCursorTextResourceEntry();
            }
            ppiStack_48 = (int **)0x1e;
            piStack_4c = (int *)0xc9;
            uStack_50 = 5;
            puStack_54 = (undefined1 *)0x182;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            thunk_ClearUiResourceContext();
            thunk_PopUiResourcePoolNode();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x5b;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructPictureResourceEntryType606E8();
            }
            ppiStack_48 = (int **)0x38;
            piStack_4c = (int *)0x3c;
            uStack_50 = 0x86;
            puStack_54 = (undefined1 *)0xd;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43b600;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
            thunk_PopUiResourcePoolNode();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x5c;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructPictureResourceEntryType606E8();
            }
            ppiStack_48 = (int **)0x38;
            piStack_4c = (int *)0x3c;
            uStack_50 = 0xbe;
            puStack_54 = (undefined1 *)0xd;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43b689;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
            thunk_PopUiResourcePoolNode();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x5d;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructPictureResourceEntryType606E8();
            }
            ppiStack_48 = (int **)0x38;
            piStack_4c = (int *)0x3c;
            uStack_50 = 0xf5;
            puStack_54 = (undefined1 *)0xd;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43b712;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
            thunk_PopUiResourcePoolNode();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x5e;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructPictureResourceEntryType606E8();
            }
            ppiStack_48 = (int **)0x38;
            piStack_4c = (int *)0x3c;
            uStack_50 = 300;
            puStack_54 = (undefined1 *)0xd;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43b79b;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
            thunk_PopUiResourcePoolNode();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x5f;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructPictureResourceEntryType606E8();
            }
            ppiStack_48 = (int **)0x38;
            piStack_4c = (int *)0x3c;
            uStack_50 = 0x164;
            puStack_54 = (undefined1 *)0xd;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43b824;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
            thunk_PopUiResourcePoolNode();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x60;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructPictureResourceEntryType606E8();
            }
            ppiStack_48 = (int **)0x38;
            piStack_4c = (int *)0x3c;
            uStack_50 = 0x86;
            puStack_54 = (undefined1 *)0x237;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43b8b0;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
            thunk_PopUiResourcePoolNode();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x61;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructPictureResourceEntryType606E8();
            }
            ppiStack_48 = (int **)0x38;
            piStack_4c = (int *)0x3c;
            uStack_50 = 0xbe;
            puStack_54 = (undefined1 *)0x237;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43b93c;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
            thunk_PopUiResourcePoolNode();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x62;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructPictureResourceEntryType606E8();
            }
            ppiStack_48 = (int **)0x38;
            piStack_4c = (int *)0x3c;
            uStack_50 = 0xf5;
            puStack_54 = (undefined1 *)0x237;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43b9c8;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
            thunk_PopUiResourcePoolNode();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 99;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructPictureResourceEntryType606E8();
            }
            ppiStack_48 = (int **)0x38;
            piStack_4c = (int *)0x3c;
            uStack_50 = 300;
            puStack_54 = (undefined1 *)0x237;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43ba54;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
            thunk_PopUiResourcePoolNode();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 100;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructPictureResourceEntryType606E8();
            }
            ppiStack_48 = (int **)0x38;
            piStack_4c = (int *)0x3c;
            uStack_50 = 0x164;
            puStack_54 = (undefined1 *)0x237;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43bae0;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
            thunk_PopUiResourcePoolNode();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x65;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructUiResourceEntryTypeB();
            }
            ppiStack_48 = (int **)0x2e;
            piStack_4c = (int *)0x28;
            uStack_50 = 0x24;
            puStack_54 = (undefined1 *)0x25a;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0x5;
            piStack_4c = (int *)0x43bb69;
            thunk_SetUiResourceLayoutValues();
            thunk_SetUiResourceContextStringCode();
            thunk_ClearUiResourceContext();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x66;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructUiTabCursorPictureEntry();
            }
            ppiStack_48 = (int **)0x26;
            piStack_4c = (int *)0x16;
            uStack_50 = 3;
            puStack_54 = (undefined1 *)0x6;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43bbe2;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
            thunk_PopUiResourcePoolNode();
          }
          else {
            if (in_stack_00000008 != 0x11f8) {
              if (in_stack_00000008 != 15000) goto LAB_0043b084;
              iVar2 = AllocateWithFallbackHandler();
              local_4 = 5;
              if (iVar2 == 0) {
                piVar3 = (int *)0x0;
              }
              else {
                piVar3 = (int *)thunk_ConstructUiWindowResourceEntryBase();
              }
              local_4 = 0xffffffff;
              if (g_pUiResourceHead == (int *)0x0) {
                uVar5 = 0;
                g_pUiResourceHead = piVar3;
              }
              else {
                uVar5 = *(undefined4 *)(DAT_006a13e8 + 8);
              }
              g_pUiResourceContext = piVar3;
              thunk_PushUiResourcePoolNode();
              ppiStack_48 = &local_24;
              uStack_50 = 0;
              local_1c = (int *)0xc8;
              local_18 = 200;
              local_24 = (int *)0x9c;
              local_20 = 0x38;
              puStack_54 = (undefined1 *)0x43b12b;
              piStack_4c = (int *)uVar5;
              thunk_InitializeUiResourceEntryFrameAndParent();
              iVar2 = *piVar3;
              piVar3[7] = 0x77696e64;
              piVar3[0xf] = 0;
              (**(code **)(iVar2 + 0xa4))();
              ppiStack_48 = (int **)0x43b14d;
              (**(code **)(iVar2 + 0xa8))();
              piVar3 = g_pUiResourceContext;
              *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
              *(undefined1 *)((int)piVar3 + 0x4d) = 1;
              piVar3 = g_pUiResourceContext;
              *(undefined1 *)(g_pUiResourceContext + 0x1c) = 0;
              *(undefined1 *)((int)piVar3 + 0x6f) = 1;
              *(undefined1 *)((int)piVar3 + 0x6e) = 1;
              *(undefined1 *)((int)piVar3 + 0x6d) = 0;
              *(undefined1 *)(piVar3 + 0x1b) = 1;
              *(undefined1 *)((int)piVar3 + 0x71) = 1;
              *(undefined2 *)(piVar3 + 0x27) = 8;
              *(undefined2 *)(piVar3 + 0x18) = 2;
              pcVar1 = *(code **)(*g_pUiResourceContext + 0x1b8);
              ppiStack_48 = (int **)0x43b196;
              piVar3 = (int *)(*pcVar1)();
              ppiStack_48 = (int **)0x1;
              piStack_4c = (int *)0x43b19f;
              (**(code **)(*piVar3 + 0x30))();
              piStack_4c = (int *)0x20202020;
              uStack_50 = 0x20202020;
              puStack_54 = (undefined1 *)0x1;
              piStack_58 = (int *)0x43b1af;
              (*pcVar1)();
              thunk_SetUiColorDescriptorGoldTriplet();
              goto LAB_0043b1b6;
            }
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x4c;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructUiResourceEntryBase();
            }
            ppiStack_48 = (int **)0x7d0;
            piStack_4c = (int *)0x7d0;
            uStack_50 = 0;
            puStack_54 = (undefined1 *)0x0;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            thunk_ClearUiResourceContext();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x4d;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_ConstructPictureResourceEntryBase();
            }
            ppiStack_48 = (int **)0x1e0;
            piStack_4c = (int *)0x280;
            uStack_50 = 0;
            puStack_54 = (undefined1 *)0x0;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            thunk_FUN_00427060();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43b2a0;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
            iVar2 = thunk_AllocateUiResourceNode();
            local_4 = 0x4e;
            if (iVar2 == 0) {
              piStack_58 = (int *)0x0;
            }
            else {
              piStack_58 = (int *)thunk_FUN_005e2230();
            }
            ppiStack_48 = (int **)0xe8;
            piStack_4c = (int *)0x11c;
            uStack_50 = 100;
            puStack_54 = (undefined1 *)0xc8;
            local_4 = 0xffffffff;
            thunk_RegisterUiResourceEntry();
            thunk_SetUiResourceStateFlags();
            ppiStack_48 = (int **)0xa;
            piStack_4c = (int *)0x43b322;
            thunk_SetUiResourceLayoutValues();
            thunk_ApplyUiResourceLayoutFromContext();
            thunk_ClearUiResourceContext();
          }
          goto LAB_0043bc09;
        }
        if (in_stack_00000008 == 0x102c) {
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x26;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiWindowResourceEntryBase();
          }
          ppiStack_48 = (int **)0x177;
          piStack_4c = (int *)0xfa;
          uStack_50 = 0x33;
          puStack_54 = (undefined1 *)0x66;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0x1;
          piStack_4c = (int *)0x0;
          uStack_50 = 2;
          puStack_54 = (undefined1 *)0x8;
          piStack_58 = (int *)0x439a88;
          thunk_SetUiResourceContextFlagsAndMetrics();
          ppiStack_48 = (int **)0x439a9e;
          thunk_ApplyUiResourceColorTripletFromContext();
          thunk_ClearUiResourceContext();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x27;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_FUN_0043d8c0();
          }
          ppiStack_48 = (int **)0x177;
          piStack_4c = (int *)0xfa;
          uStack_50 = 0;
          puStack_54 = (undefined1 *)0x0;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xa;
          piStack_4c = (int *)0x439b0e;
          thunk_SetUiResourceLayoutValues();
          thunk_ApplyUiResourceLayoutFromContext();
          thunk_ClearUiResourceContext();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x28;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructSelectableTextOptionEntryBase();
          }
          ppiStack_48 = (int **)0xf;
          piStack_4c = (int *)0x81;
          uStack_50 = 0x16;
          puStack_54 = (undefined1 *)0x62;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x439b8a;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = &DAT_006a13a0;
          uStack_50 = 0xffffffff;
          puStack_54 = (undefined1 *)0x5e5;
          piStack_58 = (int *)0x439bb3;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x29;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructSelectableTextOptionEntryBase();
          }
          ppiStack_48 = (int **)0x12;
          piStack_4c = (int *)0x74;
          uStack_50 = 0x6d;
          puStack_54 = (undefined1 *)0x68;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x439c2c;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = &DAT_006a13a0;
          uStack_50 = 0xffffffff;
          puStack_54 = (undefined1 *)0x5e5;
          piStack_58 = (int *)0x439c55;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x2a;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructSelectableTextOptionEntryBase();
          }
          ppiStack_48 = (int **)0x12;
          piStack_4c = (int *)0x77;
          uStack_50 = 0xc1;
          puStack_54 = (undefined1 *)0x55;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x439cd1;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = &DAT_006a13a0;
          uStack_50 = 0xffffffff;
          puStack_54 = (undefined1 *)0x5e5;
          piStack_58 = (int *)0x439cf9;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x2b;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructSelectableTextOptionEntryBase();
          }
          ppiStack_48 = (int **)0x13;
          piStack_4c = (int *)0x90;
          uStack_50 = 0x9a;
          puStack_54 = (undefined1 *)0x55;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x439d78;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = &DAT_006a13a0;
          uStack_50 = 0xffffffff;
          puStack_54 = (undefined1 *)0x5e5;
          piStack_58 = (int *)0x439da0;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x2c;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructSelectableTextOptionEntryBase();
          }
          ppiStack_48 = (int **)0x11;
          piStack_4c = (int *)0x8a;
          uStack_50 = 0xe7;
          puStack_54 = (undefined1 *)0x55;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x439e1f;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = &DAT_006a13a0;
          uStack_50 = 0xffffffff;
          puStack_54 = (undefined1 *)0x5e5;
          piStack_58 = (int *)0x439e47;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x2d;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructSelectableTextOptionEntryBase();
          }
          ppiStack_48 = (int **)0xf;
          piStack_4c = (int *)0x7c;
          uStack_50 = 0x10c;
          puStack_54 = (undefined1 *)0x55;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x439ec3;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = &DAT_006a13a0;
          uStack_50 = 0xffffffff;
          puStack_54 = (undefined1 *)0x5e5;
          piStack_58 = (int *)0x439eeb;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x2e;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructSelectableTextOptionEntryBase();
          }
          ppiStack_48 = (int **)0x12;
          piStack_4c = (int *)0x7e;
          uStack_50 = 0x12f;
          puStack_54 = (undefined1 *)0x55;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x439f67;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = &DAT_006a13a0;
          uStack_50 = 0xffffffff;
          puStack_54 = (undefined1 *)0x5e5;
          piStack_58 = (int *)0x439f8f;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x2f;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTabCursorPictureEntry();
          }
          ppiStack_48 = (int **)0x25;
          piStack_4c = (int *)0x61;
          uStack_50 = 0x41;
          puStack_54 = (undefined1 *)0x70;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xa;
          piStack_4c = (int *)0x43a008;
          thunk_SetUiResourceLayoutValues();
          thunk_ApplyUiResourceLayoutFromContext();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x30;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTabCursorPictureEntry();
          }
          ppiStack_48 = (int **)0x1b;
          piStack_4c = (int *)0x41;
          uStack_50 = 0x95;
          puStack_54 = (undefined1 *)0xa;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xa;
          piStack_4c = (int *)0x43a091;
          thunk_SetUiResourceLayoutValues();
          thunk_ApplyUiResourceLayoutFromContext();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x31;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTabCursorPictureEntry();
          }
          ppiStack_48 = (int **)0x1b;
          piStack_4c = (int *)0x41;
          uStack_50 = 0xba;
          puStack_54 = (undefined1 *)0xa;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xa;
          piStack_4c = (int *)0x43a11a;
          thunk_SetUiResourceLayoutValues();
          thunk_ApplyUiResourceLayoutFromContext();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x32;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTabCursorPictureEntry();
          }
          ppiStack_48 = (int **)0x1b;
          piStack_4c = (int *)0x41;
          uStack_50 = 0xdf;
          puStack_54 = (undefined1 *)0xa;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xa;
          piStack_4c = (int *)0x43a1a3;
          thunk_SetUiResourceLayoutValues();
          thunk_ApplyUiResourceLayoutFromContext();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x33;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTabCursorPictureEntry();
          }
          ppiStack_48 = (int **)0x1b;
          piStack_4c = (int *)0x41;
          uStack_50 = 0x104;
          puStack_54 = (undefined1 *)0xa;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xa;
          piStack_4c = (int *)0x43a22c;
          thunk_SetUiResourceLayoutValues();
          thunk_ApplyUiResourceLayoutFromContext();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x34;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTabCursorPictureEntry();
          }
          ppiStack_48 = (int **)0x1b;
          piStack_4c = (int *)0x41;
          uStack_50 = 0x129;
          puStack_54 = (undefined1 *)0xa;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xa;
          piStack_4c = (int *)0x43a2b5;
          thunk_SetUiResourceLayoutValues();
          thunk_ApplyUiResourceLayoutFromContext();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x35;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTabCursorPictureEntry();
          }
          ppiStack_48 = (int **)0x1b;
          piStack_4c = (int *)0x41;
          uStack_50 = 0x14f;
          puStack_54 = (undefined1 *)0xb;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0x22;
          piStack_4c = (int *)0x43a33e;
          thunk_SetUiResourceLayoutValues();
          thunk_ApplyUiResourceLayoutFromContext();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x36;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructSelectableTextOptionEntryBase();
          }
          ppiStack_48 = (int **)0x12;
          piStack_4c = (int *)0x7e;
          uStack_50 = 0x154;
          puStack_54 = (undefined1 *)0x54;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x43a3c7;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = &DAT_006a13a0;
          uStack_50 = 0xffffffff;
          puStack_54 = (undefined1 *)0x5e5;
          piStack_58 = (int *)0x43a3ef;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
        }
        else {
          if (in_stack_00000008 != 0x101a) goto LAB_0043b084;
          iVar2 = AllocateWithFallbackHandler();
          local_4 = 0x15;
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiWindowResourceEntryBase();
          }
          local_4 = 0xffffffff;
          if (g_pUiResourceHead == (int *)0x0) {
            uVar5 = 0;
            g_pUiResourceHead = piVar3;
          }
          else {
            uVar5 = *(undefined4 *)(DAT_006a13e8 + 8);
          }
          g_pUiResourceContext = piVar3;
          thunk_PushUiResourcePoolNode();
          ppiStack_48 = &local_24;
          uStack_50 = 0;
          local_1c = (int *)0xfa;
          local_18 = 0x177;
          local_24 = (int *)0xb4;
          local_20 = 0x3f;
          puStack_54 = (undefined1 *)0x438cda;
          piStack_4c = (int *)uVar5;
          thunk_InitializeUiResourceEntryFrameAndParent();
          iVar2 = *piVar3;
          piVar3[7] = 0x57494e44;
          piVar3[0xf] = 0;
          (**(code **)(iVar2 + 0xa4))();
          ppiStack_48 = (int **)0x438cfc;
          (**(code **)(iVar2 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x1c) = 0;
          *(undefined1 *)((int)piVar3 + 0x6f) = 1;
          *(undefined1 *)((int)piVar3 + 0x6e) = 1;
          *(undefined1 *)((int)piVar3 + 0x6d) = 0;
          *(undefined1 *)(piVar3 + 0x1b) = 0;
          *(undefined1 *)((int)piVar3 + 0x71) = 1;
          *(undefined2 *)(piVar3 + 0x27) = 8;
          *(undefined2 *)(piVar3 + 0x18) = 2;
          pcVar1 = *(code **)(*g_pUiResourceContext + 0x1b8);
          ppiStack_48 = (int **)0x438d44;
          piVar3 = (int *)(*pcVar1)();
          ppiStack_48 = (int **)0x1;
          piStack_4c = (int *)0x438d4d;
          (**(code **)(*piVar3 + 0x30))();
          piStack_4c = (int *)0x20202020;
          uStack_50 = 0x20202020;
          puStack_54 = (undefined1 *)0x1;
          piStack_58 = (int *)0x438d5d;
          (*pcVar1)();
          piStack_58 = (int *)0x438d64;
          thunk_SetUiColorDescriptorGoldTriplet();
          piStack_4c = (int *)0x90;
          g_pUiResourceContext = (int *)0x0;
          uStack_50 = 0x438d74;
          piVar3 = (int *)AllocateWithFallbackHandler();
          local_18 = 0x16;
          local_c = piVar3;
          if (piVar3 == (int *)0x0) {
            piVar3 = (int *)0x0;
          }
          else {
            piStack_4c = (int *)0x438d90;
            thunk_ConstructPictureResourceEntryBase();
            *piVar3 = (int)&PTR_LAB_006415b8;
          }
          local_18 = 0xffffffff;
          piVar4 = piVar3;
          if (g_pUiResourceHead != (int *)0x0) {
            piVar4 = g_pUiResourceHead;
          }
          g_pUiResourceHead = piVar4;
          uStack_50 = 0x438dca;
          g_pUiResourceContext = piVar3;
          piStack_4c = piVar3;
          thunk_PushUiResourcePoolNode();
          piStack_4c = (int *)0x1;
          uStack_50 = 0;
          piStack_58 = (int *)&stack0xffffffd0;
          puStack_54 = (undefined1 *)0x0;
          thunk_InitializeUiResourceEntryFrameAndParent();
          iVar2 = *piVar3;
          piStack_4c = (int *)0x0;
          uStack_50 = 1;
          piVar3[7] = 0x444c4f47;
          piVar3[0xf] = 0;
          puStack_54 = (undefined1 *)0x438e10;
          (**(code **)(iVar2 + 0xa4))();
          puStack_54 = (undefined1 *)0x0;
          piStack_58 = (int *)0x0;
          (**(code **)(iVar2 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 10;
          iStack_6c = 0x438e41;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffffc0,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          (**(code **)(*g_pUiResourceContext + 0x1c8))();
          g_pUiResourceContext = (int *)0x0;
          local_24 = (int *)AllocateWithFallbackHandler();
          if (local_24 == (int *)0x0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiTabCursorPictureEntry();
          }
          piVar4 = piVar3;
          if (g_pUiResourceHead != (int *)0x0) {
            piVar4 = g_pUiResourceHead;
          }
          g_pUiResourceHead = piVar4;
          g_pUiResourceContext = piVar3;
          thunk_PushUiResourcePoolNode();
          pppiStack_70 = &ppiStack_48;
          iStack_6c = 0;
          ppiStack_48 = (int **)0x61;
          uStack_50 = 0x71;
          piStack_4c = (int *)0x41;
          thunk_InitializeUiResourceEntryFrameAndParent();
          iVar2 = *piVar3;
          piVar3[7] = 0x61647669;
          piVar3[0xf] = 0;
          iStack_6c = 0x438f1b;
          (**(code **)(iVar2 + 0xa4))();
          iStack_6c = 0;
          pppiStack_70 = (int ***)0x1;
          (**(code **)(iVar2 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 10;
          piVar4 = (int *)CRect::CRect((CRect *)&piStack_58,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          (**(code **)(*g_pUiResourceContext + 0x1c8))();
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          iVar2 = AllocateWithFallbackHandler();
          ppiStack_48 = (int **)0x18;
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiBattleTabPictureEntry();
          }
          ppiStack_48 = (int **)0xffffffff;
          piVar4 = piVar3;
          if (g_pUiResourceHead != (int *)0x0) {
            piVar4 = g_pUiResourceHead;
          }
          g_pUiResourceHead = piVar4;
          g_pUiResourceContext = piVar3;
          thunk_PushUiResourcePoolNode();
          thunk_InitializeUiResourceEntryFrameAndParent();
          iVar2 = *piVar3;
          piVar3[7] = 0x6f726566;
          piVar3[0xf] = 0x1022;
          (**(code **)(iVar2 + 0xa4))();
          (**(code **)(iVar2 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 10;
          piVar4 = (int *)CRect::CRect((CRect *)&pppiStack_70,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          (**(code **)(*g_pUiResourceContext + 0x1c8))();
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          puStack_54 = (undefined1 *)AllocateWithFallbackHandler();
          if (puStack_54 == (undefined1 *)0x0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiBattleTabPictureEntry();
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
          piVar3[7] = 0x6e657773;
          piVar3[0xf] = 0x1023;
          (**(code **)(iVar2 + 0xa4))();
          (**(code **)(iVar2 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 10;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff78,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          (**(code **)(*g_pUiResourceContext + 0x1c8))();
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          iStack_6c = AllocateWithFallbackHandler();
          if (iStack_6c == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiBattleTabPictureEntry();
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
          piVar3[7] = 0x6465616c;
          piVar3[0xf] = 0x1024;
          (**(code **)(iVar2 + 0xa4))();
          (**(code **)(iVar2 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 10;
          piVar4 = (int *)CRect::CRect((CRect *)&stack0xffffff60,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          (**(code **)(*g_pUiResourceContext + 0x1c8))();
          g_pUiResourceContext = (int *)0x0;
          thunk_PopUiResourcePoolNode();
          iVar2 = AllocateWithFallbackHandler();
          if (iVar2 == 0) {
            piVar3 = (int *)0x0;
          }
          else {
            piVar3 = (int *)thunk_ConstructUiBattleTabPictureEntry();
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
          piVar3[7] = 0x62617474;
          piVar3[0xf] = 0x1025;
          (**(code **)(iVar2 + 0xa4))();
          (**(code **)(iVar2 + 0xa8))();
          piVar3 = g_pUiResourceContext;
          *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
          *(undefined1 *)((int)piVar3 + 0x4d) = 1;
          piVar3 = g_pUiResourceContext;
          g_pUiResourceContext[0x18] = 10;
          ppiStack_48 = (int **)0x4393b5;
          piVar4 = (int *)CRect::CRect((CRect *)&local_1c,0,0,0,0);
          piVar3[0x1a] = *piVar4;
          piVar3[0x1b] = piVar4[1];
          piVar3[0x1c] = piVar4[2];
          piVar3[0x1d] = piVar4[3];
          thunk_ApplyUiResourceLayoutFromContext();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x1c;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiBattleTabPictureEntry();
          }
          ppiStack_48 = (int **)0x1b;
          piStack_4c = (int *)0x41;
          uStack_50 = 0x12a;
          puStack_54 = (undefined1 *)0xc;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xa;
          piStack_4c = (int *)0x439458;
          thunk_SetUiResourceLayoutValues();
          thunk_ApplyUiResourceLayoutFromContext();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x1d;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTabCursorPictureEntry();
          }
          ppiStack_48 = (int **)0x1b;
          piStack_4c = (int *)0x41;
          uStack_50 = 0x14f;
          puStack_54 = (undefined1 *)0xa;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xa;
          piStack_4c = (int *)0x4394e1;
          thunk_SetUiResourceLayoutValues();
          thunk_ApplyUiResourceLayoutFromContext();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x1e;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTextResourceEntryBase();
          }
          ppiStack_48 = (int **)0x10;
          piStack_4c = (int *)0x7e;
          uStack_50 = 0x16;
          puStack_54 = (undefined1 *)0x65;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x439567;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = (int *)s_Static_Text_00694354;
          uStack_50 = 0x10;
          puStack_54 = (undefined1 *)0x3e9;
          piStack_58 = (int *)0x43958c;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x1f;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTextResourceEntryBase();
          }
          ppiStack_48 = (int **)0xf;
          piStack_4c = (int *)0x90;
          uStack_50 = 0x9c;
          puStack_54 = (undefined1 *)0x5b;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x43960b;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = (int *)s_Static_Text_00694354;
          uStack_50 = 0x10;
          puStack_54 = (undefined1 *)0x3e9;
          piStack_58 = (int *)0x439630;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x20;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTextResourceEntryBase();
          }
          ppiStack_48 = (int **)0xf;
          piStack_4c = (int *)0x90;
          uStack_50 = 0xc0;
          puStack_54 = (undefined1 *)0x5b;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x4396af;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = (int *)s_Static_Text_00694354;
          uStack_50 = 0x10;
          puStack_54 = (undefined1 *)0x3e9;
          piStack_58 = (int *)0x4396d4;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x21;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTextResourceEntryBase();
          }
          ppiStack_48 = (int **)0xf;
          piStack_4c = (int *)0x90;
          uStack_50 = 0xe6;
          puStack_54 = (undefined1 *)0x5b;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x439753;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = (int *)s_Static_Text_00694354;
          uStack_50 = 0x10;
          puStack_54 = (undefined1 *)0x3e9;
          piStack_58 = (int *)0x439778;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x22;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTextResourceEntryBase();
          }
          ppiStack_48 = (int **)0xf;
          piStack_4c = (int *)0x90;
          uStack_50 = 0x10a;
          puStack_54 = (undefined1 *)0x5b;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x4397f7;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = (int *)s_Static_Text_00694354;
          uStack_50 = 0x10;
          puStack_54 = (undefined1 *)0x3e9;
          piStack_58 = (int *)0x43981c;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x23;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTextResourceEntryBase();
          }
          ppiStack_48 = (int **)0xf;
          piStack_4c = (int *)0x90;
          uStack_50 = 0x130;
          puStack_54 = (undefined1 *)0x5b;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x43989b;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = (int *)s_Static_Text_00694354;
          uStack_50 = 0x10;
          puStack_54 = (undefined1 *)0x3e9;
          piStack_58 = (int *)0x4398c0;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x24;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTextResourceEntryBase();
          }
          ppiStack_48 = (int **)0xf;
          piStack_4c = (int *)0x90;
          uStack_50 = 0x154;
          puStack_54 = (undefined1 *)0x5b;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x43993f;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = (int *)s_Static_Text_00694354;
          uStack_50 = 0x10;
          puStack_54 = (undefined1 *)0x3e9;
          piStack_58 = (int *)0x439964;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
          thunk_PopUiResourcePoolNode();
          iVar2 = thunk_AllocateUiResourceNode();
          local_4 = 0x25;
          if (iVar2 == 0) {
            piStack_58 = (int *)0x0;
          }
          else {
            piStack_58 = (int *)thunk_ConstructUiTextResourceEntryBase();
          }
          ppiStack_48 = (int **)0xf;
          piStack_4c = (int *)0x90;
          uStack_50 = 0x73;
          puStack_54 = (undefined1 *)0x59;
          local_4 = 0xffffffff;
          thunk_RegisterUiResourceEntry();
          thunk_SetUiResourceStateFlags();
          ppiStack_48 = (int **)0xd;
          piStack_4c = (int *)0x4399e0;
          thunk_SetUiResourceLayoutValues();
          thunk_SetUiResourceContextTagWord();
          ppiStack_48 = (int **)0x0;
          piStack_4c = (int *)s_Static_Text_00694354;
          uStack_50 = 0x10;
          puStack_54 = (undefined1 *)0x3e9;
          piStack_58 = (int *)0x439a05;
          thunk_BindUiResourceTextAndStyle();
          thunk_ClearUiResourceContext();
        }
      }
      goto LAB_0043a3fc;
    }
    if (in_stack_00000008 != 0x5de) {
      if (in_stack_00000008 != 0x3ea) goto LAB_0043b084;
      iVar2 = AllocateWithFallbackHandler();
      local_4 = 0;
      if (iVar2 == 0) {
        piVar3 = (int *)0x0;
      }
      else {
        piVar3 = (int *)thunk_ConstructUiResourceEntryBase();
      }
      local_4 = 0xffffffff;
      if (g_pUiResourceHead == (int *)0x0) {
        pcVar6 = (char *)0x0;
        g_pUiResourceHead = piVar3;
      }
      else {
        pcVar6 = *(char **)(DAT_006a13e8 + 8);
      }
      g_pUiResourceContext = piVar3;
      thunk_PushUiResourcePoolNode();
      ppiStack_48 = &local_1c;
      uStack_50 = 0;
      local_24 = (int *)0x19e;
      local_20 = 0x86;
      local_1c = (int *)0x0;
      local_18 = 0;
      puStack_54 = (undefined1 *)0x435ef7;
      piStack_4c = (int *)pcVar6;
      thunk_InitializeUiResourceEntryFrameAndParent();
      iVar2 = *piVar3;
      piVar3[7] = 0x44464c54;
      piVar3[0xf] = 0;
      (**(code **)(iVar2 + 0xa4))();
      ppiStack_48 = (int **)0x435f19;
      (**(code **)(iVar2 + 0xa8))();
      *(undefined1 *)(g_pUiResourceContext + 0x13) = 1;
      *(undefined1 *)((int)g_pUiResourceContext + 0x4d) = 1;
LAB_0043b1b6:
      g_pUiResourceContext = (int *)0x0;
      thunk_PopUiResourcePoolNode();
      goto LAB_0043bc2b;
    }
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x67;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiResourceEntryBase();
    }
    ppiStack_48 = (int **)0x1e0;
    piStack_4c = (int *)0x280;
    uStack_50 = 0;
    puStack_54 = (undefined1 *)0x0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x68;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiBaseBackdropPictureEntry();
    }
    ppiStack_48 = (int **)0x1e0;
    piStack_4c = (int *)0x280;
    uStack_50 = 0;
    puStack_54 = (undefined1 *)0x0;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    ppiStack_48 = (int **)0xa;
    piStack_4c = (int *)0x435ff1;
    thunk_SetUiResourceLayoutValues();
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x69;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
    }
    ppiStack_48 = (int **)0x15;
    piStack_4c = (int *)0xe1;
    uStack_50 = 0x122;
    puStack_54 = (undefined1 *)0x48;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    ppiStack_48 = (int **)0xd;
    piStack_4c = (int *)0x436071;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    ppiStack_48 = (int **)0x0;
    piStack_4c = (int *)s_Static_Text_00694354;
    uStack_50 = 0x10;
    puStack_54 = (undefined1 *)0x3e9;
    piStack_58 = (int *)0x436096;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x6a;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
    }
    ppiStack_48 = (int **)0x15;
    piStack_4c = (int *)0xe1;
    uStack_50 = 0x146;
    puStack_54 = (undefined1 *)0x48;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    ppiStack_48 = (int **)0xd;
    piStack_4c = (int *)0x436116;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    ppiStack_48 = (int **)0x0;
    piStack_4c = (int *)s_Static_Text_00694354;
    uStack_50 = 0x10;
    puStack_54 = (undefined1 *)0x3e9;
    piStack_58 = (int *)0x43613b;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x6b;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
    }
    ppiStack_48 = (int **)0x15;
    piStack_4c = (int *)0xe1;
    uStack_50 = 0x18a;
    puStack_54 = (undefined1 *)0x49;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    ppiStack_48 = (int **)0xd;
    piStack_4c = (int *)0x4361bb;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    ppiStack_48 = (int **)0x0;
    piStack_4c = (int *)s_Static_Text_00694354;
    uStack_50 = 0x10;
    puStack_54 = (undefined1 *)0x3e9;
    piStack_58 = (int *)0x4361e0;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x6c;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
    }
    ppiStack_48 = (int **)0x15;
    piStack_4c = (int *)0xe1;
    uStack_50 = 0x168;
    puStack_54 = (undefined1 *)0x49;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    ppiStack_48 = (int **)0xd;
    piStack_4c = (int *)0x436260;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    ppiStack_48 = (int **)0x0;
    piStack_4c = (int *)s_Static_Text_00694354;
    uStack_50 = 0x10;
    puStack_54 = (undefined1 *)0x3e9;
    piStack_58 = (int *)0x436285;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x6d;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
    }
    ppiStack_48 = (int **)0x15;
    piStack_4c = (int *)0xe1;
    uStack_50 = 0x18a;
    puStack_54 = (undefined1 *)0x15a;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    ppiStack_48 = (int **)0xd;
    piStack_4c = (int *)0x436308;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    ppiStack_48 = (int **)0x0;
    piStack_4c = (int *)s_Static_Text_00694354;
    uStack_50 = 0x10;
    puStack_54 = (undefined1 *)0x3e9;
    piStack_58 = (int *)0x43632d;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x6e;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
    }
    ppiStack_48 = (int **)0x15;
    piStack_4c = (int *)0xe1;
    uStack_50 = 0x168;
    puStack_54 = (undefined1 *)0x15a;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    ppiStack_48 = (int **)0xd;
    piStack_4c = (int *)0x4363b0;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    ppiStack_48 = (int **)0x0;
    piStack_4c = (int *)s_Static_Text_00694354;
    uStack_50 = 0x10;
    puStack_54 = (undefined1 *)0x3e9;
    piStack_58 = (int *)0x4363d5;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x6f;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
    }
    ppiStack_48 = (int **)0x15;
    piStack_4c = (int *)0xe1;
    uStack_50 = 0x146;
    puStack_54 = (undefined1 *)0x159;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    ppiStack_48 = (int **)0xd;
    piStack_4c = (int *)0x436458;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    ppiStack_48 = (int **)0x0;
    piStack_4c = (int *)s_Static_Text_00694354;
    uStack_50 = 0x10;
    puStack_54 = (undefined1 *)0x3e9;
    piStack_58 = (int *)0x43647d;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x70;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiStatusListTextEntry();
    }
    ppiStack_48 = (int **)0x15;
    piStack_4c = (int *)0xe1;
    uStack_50 = 0x122;
    puStack_54 = (undefined1 *)0x159;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    ppiStack_48 = (int **)0xd;
    piStack_4c = (int *)0x436500;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    ppiStack_48 = (int **)0x0;
    piStack_4c = (int *)s_Static_Text_00694354;
    uStack_50 = 0x10;
    puStack_54 = (undefined1 *)0x3e9;
    piStack_58 = (int *)0x436525;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x71;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiCommandTagResourceEntry();
    }
    ppiStack_48 = (int **)0xfc;
    piStack_4c = (int *)0x43;
    uStack_50 = 0xdd;
    puStack_54 = (undefined1 *)0x2;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    ppiStack_48 = (int **)0x14;
    piStack_4c = (int *)0x4365a4;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x72;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructPictureResourceEntryBase();
    }
    ppiStack_48 = (int **)0xff;
    piStack_4c = (int *)0x15e;
    uStack_50 = 1;
    puStack_54 = (undefined1 *)0x122;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    ppiStack_48 = (int **)0xa;
    piStack_4c = (int *)0x436625;
    thunk_SetUiResourceLayoutValues();
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x73;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructPictureScreenResourceEntry();
    }
    ppiStack_48 = (int **)0x1e;
    piStack_4c = (int *)0x60;
    uStack_50 = 0xcd;
    puStack_54 = (undefined1 *)0xe9;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    ppiStack_48 = (int **)0xa;
    piStack_4c = (int *)0x4366a5;
    thunk_SetUiResourceLayoutValues();
    thunk_ApplyUiResourceLayoutFromContext();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x74;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiPlanetListResourceEntry();
    }
    ppiStack_48 = (int **)0xb4;
    piStack_4c = (int *)0x144;
    uStack_50 = 0xd;
    puStack_54 = (undefined1 *)0xc;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x75;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiTextResourceEntryBase();
    }
    ppiStack_48 = (int **)0x2b;
    piStack_4c = (int *)0xcd;
    uStack_50 = 0xc5;
    puStack_54 = (undefined1 *)0x14;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    ppiStack_48 = (int **)0xd;
    piStack_4c = (int *)0x43679f;
    thunk_SetUiResourceLayoutValues();
    thunk_SetUiResourceContextTagWord();
    ppiStack_48 = (int **)0x0;
    piStack_4c = (int *)s_Static_Text_00694354;
    uStack_50 = 0x10;
    puStack_54 = (undefined1 *)0x3e9;
    piStack_58 = (int *)0x4367c4;
    thunk_BindUiResourceTextAndStyle();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x76;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiCommandTagResourceEntryBase();
    }
    ppiStack_48 = (int **)0x31;
    piStack_4c = (int *)0xbc;
    uStack_50 = 0x50;
    puStack_54 = (undefined1 *)0x47;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    ppiStack_48 = (int **)0x14;
    piStack_4c = (int *)0x43684d;
    thunk_SetUiResourceLayoutValues();
    thunk_ClearUiResourceContext();
    thunk_PopUiResourcePoolNode();
    iVar2 = thunk_AllocateUiResourceNode();
    local_4 = 0x77;
    if (iVar2 == 0) {
      piStack_58 = (int *)0x0;
    }
    else {
      piStack_58 = (int *)thunk_ConstructUiCursorTextResourceEntry();
    }
    ppiStack_48 = (int **)0x1e;
    piStack_4c = (int *)0xc9;
    uStack_50 = 0x13;
    puStack_54 = (undefined1 *)0x31;
    local_4 = 0xffffffff;
    thunk_RegisterUiResourceEntry();
    thunk_SetUiResourceStateFlags();
    thunk_ClearUiResourceContext();
LAB_0043bc09:
    thunk_PopUiResourcePoolNode();
    thunk_PopUiResourcePoolNode();
  }
  thunk_PopUiResourcePoolNode();
LAB_0043bc2b:
  if (g_pUiResourceHead != (int *)0x0) {
    thunk_PropagateUiResourceContextRecursive();
  }
  piVar3 = g_pUiResourceHead;
  *unaff_FS_OFFSET = local_c;
  return piVar3;
}

