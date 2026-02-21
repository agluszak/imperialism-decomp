
void __fastcall FUN_0055b820(int *param_1)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = param_1 + 0x3b5;
  iVar2 = 7;
  do {
    if ((int *)*piVar1 != (int *)0x0) {
      (**(code **)(*(int *)*piVar1 + 0x24))();
    }
    if (piVar1[8] != 0) {
      FreeHeapBufferIfNotNull(piVar1[8]);
    }
    piVar1 = piVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  if ((int *)param_1[0x3bc] != (int *)0x0) {
    (**(code **)(*(int *)param_1[0x3bc] + 0x24))();
  }
  if (param_1 != (int *)0x0) {
    (**(code **)(*param_1 + 4))(1);
  }
  return;
}

