
void __thiscall FUN_005549a0(int param_1,int param_2,char param_3)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0x10);
  if (piVar1 == (int *)0x0) {
    piVar1 = (int *)0x0;
  }
  else if (*piVar1 != param_2) {
    piVar1 = FindMissionOrderNodeById((void *)piVar1[1],param_2);
  }
  if ((piVar1 != (int *)0x0) && (*(char *)(piVar1 + 3) = param_3, param_3 != '\0')) {
    *(undefined4 *)(param_2 + 0x34) = 0;
  }
  return;
}

