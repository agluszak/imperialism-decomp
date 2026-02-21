
void __fastcall thunk_FUN_0048d670(undefined4 *param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 uStack_4;
  
  puStack_8 = &LAB_0062ee26;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  *param_1 = &PTR_LAB_00649e58;
  uStack_4 = 1;
  for (piVar1 = DAT_006a1a44; piVar1 != (int *)0x0; piVar1 = (int *)*piVar1) {
    if ((undefined4 *)piVar1[2] == param_1) goto LAB_0048d6b8;
  }
  piVar1 = (int *)0x0;
LAB_0048d6b8:
  if (piVar1 == DAT_006a1a44) {
    DAT_006a1a44 = (int *)*piVar1;
  }
  else {
    *(int *)piVar1[1] = *piVar1;
  }
  if (piVar1 == DAT_006a1a48) {
    DAT_006a1a48 = (int *)piVar1[1];
  }
  else {
    *(int *)(*piVar1 + 4) = piVar1[1];
  }
  *piVar1 = (int)DAT_006a1a50;
  DAT_006a1a4c = DAT_006a1a4c + -1;
  puVar2 = DAT_006a1ac4;
  DAT_006a1a50 = piVar1;
  if (DAT_006a1a4c == 0) {
    for (; DAT_006a1a44 != (int *)0x0; DAT_006a1a44 = (int *)*DAT_006a1a44) {
    }
    DAT_006a1a4c = 0;
    DAT_006a1a50 = (int *)0x0;
    DAT_006a1a48 = (int *)0x0;
    DAT_006a1a44 = (int *)0x0;
    FreeLinkedBlockChain();
    DAT_006a1a54 = 0;
    puVar2 = DAT_006a1ac4;
  }
  for (; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
    if ((undefined4 *)puVar2[2] == param_1) goto LAB_0048d750;
  }
  puVar2 = (undefined4 *)0x0;
LAB_0048d750:
  if (((puVar2 != (undefined4 *)0x0) &&
      (thunk_FUN_00492550(puVar2), DAT_006a1ac4 != (undefined4 *)0x0)) &&
     (piVar1 = (int *)DAT_006a1ac4[2], (**(code **)(*piVar1 + 0xc))(), piVar1[0x14] != 0)) {
    FUN_0060753b(1);
  }
  param_1[0x1d] = &PTR_LAB_0066fec4;
  *param_1 = &PTR_LAB_00649858;
  uStack_4 = 3;
  if ((int *)param_1[0x11] != (int *)0x0) {
    (**(code **)(*(int *)param_1[0x11] + 4))(1);
  }
  FreeHeapBufferIfNotNull(param_1[0x12]);
  uStack_4 = CONCAT31(uStack_4._1_3_,2);
  ReleaseSharedStringRefIfNotEmpty();
  *param_1 = &PTR_LAB_0066fec4;
  *unaff_FS_OFFSET = uStack_c;
  return;
}

