
undefined4 __thiscall FUN_005616c0(undefined4 param_1,byte param_2)

{
  thunk_FUN_005616f0();
  if ((param_2 & 1) != 0) {
    FreeHeapBufferIfNotNull(param_1);
  }
  return param_1;
}

