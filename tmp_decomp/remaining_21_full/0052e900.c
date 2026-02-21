// 0x0052e900 FUN_0052e900\n\n
void __fastcall FUN_0052e900(int *param_1)

{
  int *piVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  int *local_c;
  int local_8;
  int local_4;
  
  piVar1 = param_1 + 4;
  local_8 = 0;
  local_4 = 0x195;
  local_c = piVar1;
  do {
    if ((char)*local_c == 'd') {
      pcVar2 = *(code **)(*param_1 + 0x74);
      iVar4 = local_8;
      do {
        iVar3 = (*pcVar2)(iVar4,4);
        *(char *)(iVar4 + (int)piVar1) = *(char *)(iVar3 + (int)piVar1);
        iVar4 = iVar3;
      } while (*(char *)(iVar3 + (int)piVar1) != -1);
    }
    local_8 = local_8 + 1;
    local_c = (int *)((int)local_c + 1);
    local_4 = local_4 + -1;
  } while (local_4 != 0);
  return;
}

