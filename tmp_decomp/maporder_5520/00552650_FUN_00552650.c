
undefined4 * __thiscall FUN_00552650(int param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)AllocateWithFallbackHandler(0x10);
  if (puVar1 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)0x0;
  }
  else {
    puVar1[1] = param_1;
    *puVar1 = param_2;
    puVar1[2] = 0;
    *(undefined1 *)(puVar1 + 3) = 1;
    if (param_1 != 0) {
      *(undefined4 **)(param_1 + 8) = puVar1;
    }
    if (puVar1[2] != 0) {
      *(undefined4 **)(puVar1[2] + 4) = puVar1;
    }
  }
  if (puVar1 != (undefined4 *)0x0) {
    return puVar1;
  }
                    /* WARNING: Subroutine does not return */
  MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
}

