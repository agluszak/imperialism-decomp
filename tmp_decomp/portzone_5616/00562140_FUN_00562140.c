
undefined4 __thiscall FUN_00562140(undefined4 param_1,byte param_2)

{
  thunk_FUN_00562170();
  if ((param_2 & 1) != 0) {
    FreeHeapBufferIfNotNull(param_1);
  }
  return param_1;
}

