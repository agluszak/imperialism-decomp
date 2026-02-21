
void __fastcall FUN_00503ac0(int param_1)

{
  int iVar1;
  void *this;
  void *unaff_retaddr;
  short nTileIndex;
  
  if (*(int *)(param_1 + 0xc) == 0) {
    iVar1 = (**(code **)(*g_pUiViewManager + 0x28))();
    *(int *)(param_1 + 0xc) = iVar1;
    if (iVar1 == 0) {
                    /* WARNING: Subroutine does not return */
      MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
    }
    (**(code **)(*g_pUiRuntimeContext + 0x44))(*(undefined4 *)(param_1 + 0xc));
    (**(code **)(**(int **)(param_1 + 0xc) + 0xf0))(&stack0xffffffec,0);
    (**(code **)(**(int **)(param_1 + 0xc) + 0x9c))();
  }
  nTileIndex = 0x4f47;
  this = (void *)(**(code **)(**(int **)(param_1 + 0xc) + 0x94))();
  thunk_BuildMapTileActionContextMenu(this,unaff_retaddr,nTileIndex);
  return;
}

