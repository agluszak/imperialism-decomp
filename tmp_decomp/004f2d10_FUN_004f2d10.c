
void __thiscall FUN_004f2d10(int *param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  char cVar2;
  int *piVar3;
  undefined4 unaff_EBX;
  undefined4 unaff_retaddr;
  
  piVar3 = (int *)(**(code **)(*param_1 + 0x94))(0x6261636b);
  if (piVar3 == (int *)0x0) {
                    /* WARNING: Subroutine does not return */
    MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
  }
  piVar3 = (int *)(**(code **)(*piVar3 + 0x94))(0x6f6b6179);
  if (piVar3 == (int *)0x0) {
                    /* WARNING: Subroutine does not return */
    MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
  }
  iVar1 = *piVar3;
  cVar2 = (**(code **)(iVar1 + 0xec))();
  if (cVar2 != '\0') {
    (**(code **)(iVar1 + 0xa4))(0,1);
  }
  DispatchUiMouseEventToChildrenOrSelf(unaff_EBX,unaff_retaddr,param_2,param_3);
  return;
}

