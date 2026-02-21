
uint __fastcall FUN_00553fe0(int param_1)

{
  int *pChildLinkHead;
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 0x10);
  if (piVar1 != (int *)0x0) {
    if (*(short *)(*piVar1 + 0x1c) < 1) {
      *(undefined4 *)(*piVar1 + 0xc) = 0;
      (**(code **)(*(int *)*piVar1 + 0x1c))();
      pChildLinkHead = (int *)piVar1[1];
      if (pChildLinkHead != (int *)0x0) {
        pChildLinkHead[2] = piVar1[2];
      }
      if (piVar1[2] != 0) {
        *(int *)(piVar1[2] + 4) = piVar1[1];
      }
      FreeHeapBufferIfNotNull(piVar1);
      piVar1 = thunk_PruneDefeatedMapOrderChildrenAndReturnHead(pChildLinkHead);
    }
    else {
      thunk_PruneDefeatedMapOrderChildrenAndReturnHead((int *)piVar1[1]);
    }
  }
  *(int **)(param_1 + 0x10) = piVar1;
  *(undefined4 *)(param_1 + 0x14) = 0;
  for (; piVar1 != (int *)0x0; piVar1 = (int *)piVar1[1]) {
    uVar2 = thunk_FUN_00550670(*(undefined4 *)(param_1 + 0x14),0);
    *(undefined4 *)(param_1 + 0x14) = uVar2;
  }
  if (*(uint *)(param_1 + 0x10) != 0) {
    return *(uint *)(param_1 + 0x10) & 0xffffff00;
  }
  *(undefined1 *)(param_1 + 0x26) = 1;
  return 1;
}

