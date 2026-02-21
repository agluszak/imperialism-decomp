
void __fastcall FUN_005619e0(int *param_1)

{
  int iVar1;
  short sVar2;
  
  sVar2 = (**(code **)(*param_1 + 0x4c))();
  iVar1 = *(int *)(g_pActiveMapContextState + 8) +
          ((short)*(char *)(*(int *)(g_pGlobalMapState + 0xc) + 4 + sVar2 * 0x24) + -0x17) * 0x48;
  (**(code **)param_1[9])(iVar1);
  (*(code *)**(undefined4 **)(iVar1 + 0x24))(param_1);
  return;
}

