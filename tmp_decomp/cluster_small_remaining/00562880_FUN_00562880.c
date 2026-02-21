
int __thiscall FUN_00562880(int param_1,byte param_2)

{
  if ((param_2 & 2) != 0) {
    FUN_005e7e10(param_1,0x48,*(undefined4 *)(param_1 + -4),thunk_FUN_005627a0);
    FreeHeapBufferIfNotNull(param_1 + -4);
    return param_1;
  }
  thunk_FUN_005627a0();
  if ((param_2 & 1) != 0) {
    FreeHeapBufferIfNotNull(param_1);
  }
  return param_1;
}

