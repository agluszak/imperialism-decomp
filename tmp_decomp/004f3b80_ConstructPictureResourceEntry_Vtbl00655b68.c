
undefined4 * __fastcall ConstructPictureResourceEntry_Vtbl00655b68(undefined4 *param_1)

{
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00632b00;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  thunk_ConstructPictureResourceEntryBase();
  local_4 = 0;
  CallCallbackRepeatedly(param_1 + 0x7ab,0x14,0x17,&LAB_00408436);
  local_4 = CONCAT31(local_4._1_3_,1);
  CallCallbackRepeatedly(param_1 + 0x81e,0x30,0x17,&LAB_00404d5e);
  *param_1 = &PTR_LAB_00655b68;
  param_1[0x25] = 0;
  *(undefined2 *)(param_1 + 0x26) = 0;
  *(undefined2 *)(param_1 + 0x24) = 0;
  param_1[0x27] = 0;
  param_1[0x149] = 6;
  param_1[0x2e] = 0;
  *(undefined4 *)(DAT_006a1344 + 0x28) = 1;
  *unaff_FS_OFFSET = local_c;
  return param_1;
}

