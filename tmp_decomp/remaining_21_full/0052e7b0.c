// 0x0052e7b0 FUN_0052e7b0\n\n
void __thiscall FUN_0052e7b0(int param_1,short param_2)

{
  int iVar1;
  
  *(short *)(param_1 + 0xc) = param_2;
  FreeHeapBufferIfNotNull(*(undefined4 *)(param_1 + 0x10));
  iVar1 = AllocateWithFallbackHandler((int)param_2 << 4);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  *(int *)(param_1 + 0x10) = iVar1;
  if (iVar1 != 0) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
}

