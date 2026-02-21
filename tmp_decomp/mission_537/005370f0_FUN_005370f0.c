
void FUN_005370f0(void)

{
  short sVar1;
  short sVar2;
  void *pvVar3;
  int *pMapOrderEntry;
  void *unaff_EBX;
  void *this;
  int in_stack_00000014;
  int in_stack_0000001c;
  int *in_stack_00000020;
  
  sVar1 = thunk_FUN_00550550();
  sVar2 = thunk_FUN_00550550();
  if (sVar2 <= sVar1) {
    *in_stack_00000020 = (int)unaff_EBX;
    unaff_EBX = (void *)0x0;
  }
  this = (void *)*in_stack_00000020;
  pvVar3 = this;
  for (; ((this == pvVar3 || (this == unaff_EBX)) && (this != (void *)0x0));
      this = (void *)((int)this + (((int)unaff_EBX - (int)pvVar3) / 0x38) * 0x38)) {
    pvVar3 = FindMissionOrderNodeById(*(void **)(in_stack_00000014 + 0x24),(int)this);
    *(undefined1 *)((int)pvVar3 + 0xc) = 1;
    pMapOrderEntry = GetOrCreateMissionOrderEntryForNode(this);
    if (*(int *)((int)this + 8) == in_stack_0000001c) {
      thunk_SetMapOrderType9AndQueue(pMapOrderEntry);
    }
    else {
      PromoteMapOrderChainAndQueue(pMapOrderEntry);
    }
    pvVar3 = (void *)*in_stack_00000020;
  }
  return;
}

