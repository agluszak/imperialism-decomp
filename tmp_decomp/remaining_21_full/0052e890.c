// 0x0052e890 FUN_0052e890\n\n
void __thiscall FUN_0052e890(int *param_1,short param_2)

{
  int iVar1;
  code *pcVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  
  iVar4 = (int)param_2;
  iVar5 = 0;
  iVar1 = *param_1;
  *(undefined1 *)((int)param_1 + iVar4 + 0x10) = 0xf7;
  _param_2 = 6;
  pcVar2 = *(code **)(iVar1 + 0x74);
  do {
    uVar3 = (*pcVar2)(iVar4,iVar5);
    if (((short)uVar3 != -1) && (*(char *)((short)uVar3 + 0x10 + (int)param_1) == -1)) {
      (**(code **)(*param_1 + 0x70))(uVar3);
    }
    iVar5 = iVar5 + 1;
    _param_2 = _param_2 + -1;
  } while (_param_2 != 0);
  return;
}

