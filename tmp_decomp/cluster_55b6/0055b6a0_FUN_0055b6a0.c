
undefined4 __thiscall FUN_0055b6a0(undefined4 param_1,byte param_2)

{
  thunk_FUN_0055b6d0();
  if ((param_2 & 1) != 0) {
    FreeHeapBufferIfNotNull(param_1);
  }
  return param_1;
}

