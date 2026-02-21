
int __fastcall FUN_004dd430(int *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = param_1[0x23e];
  iVar2 = (**(code **)(*param_1 + 0x17c))();
  return iVar2 + (((param_1[0x210] + param_1[0x211]) - param_1[600]) - iVar1);
}

