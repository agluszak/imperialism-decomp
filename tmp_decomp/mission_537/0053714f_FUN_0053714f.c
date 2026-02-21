
void __thiscall FUN_0053714f(int *param_1)

{
  void *pvVar1;
  void *unaff_EBX;
  int unaff_EBP;
  void *unaff_ESI;
  int in_stack_00000010;
  undefined4 *in_stack_0000001c;
  
  do {
    thunk_SetMapOrderType9AndQueue(param_1);
    while( true ) {
      unaff_ESI = (void *)((int)unaff_ESI +
                          (((int)unaff_EBX - (int)*in_stack_0000001c) / 0x38) * 0x38);
      if (((unaff_ESI != (void *)*in_stack_0000001c) && (unaff_ESI != unaff_EBX)) ||
         (unaff_ESI == (void *)0x0)) {
        return;
      }
      pvVar1 = FindMissionOrderNodeById(*(void **)(in_stack_00000010 + 0x24),(int)unaff_ESI);
      *(undefined1 *)((int)pvVar1 + 0xc) = 1;
      param_1 = GetOrCreateMissionOrderEntryForNode(unaff_ESI);
      if (*(int *)((int)unaff_ESI + 8) == unaff_EBP) break;
      PromoteMapOrderChainAndQueue(param_1);
    }
  } while( true );
}

