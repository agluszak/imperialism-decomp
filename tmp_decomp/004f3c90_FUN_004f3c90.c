
undefined4 __thiscall FUN_004f3c90(undefined4 param_1,byte param_2)

{
  thunk_FUN_004f3cc0();
  if ((param_2 & 1) != 0) {
    FreeHeapBufferIfNotNull(param_1);
  }
  return param_1;
}

