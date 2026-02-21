
void __thiscall
FUN_005b6cd0(char *param_1,char *param_2,undefined2 param_3,char param_4,undefined2 param_5)

{
  char cVar1;
  undefined2 uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  
  uVar3 = 0xffffffff;
  do {
    pcVar7 = param_2;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar7 = param_2 + 1;
    cVar1 = *param_2;
    param_2 = pcVar7;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  pcVar6 = pcVar7 + -uVar3;
  pcVar7 = param_1;
  for (uVar4 = uVar3 >> 2; pcVar7 = pcVar7 + 4, uVar4 != 0; uVar4 = uVar4 - 1) {
    *(undefined4 *)pcVar7 = *(undefined4 *)pcVar6;
    pcVar6 = pcVar6 + 4;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *pcVar7 = *pcVar6;
    pcVar6 = pcVar6 + 1;
    pcVar7 = pcVar7 + 1;
  }
  *(undefined2 *)(param_1 + 0x1c) = param_5;
  *(undefined2 *)(param_1 + 0x14) = param_3;
  param_1[0x4d] = param_4;
  param_1[0x4f] = param_4 == '\0';
  param_1[0x16] = '\0';
  param_1[0x17] = '\0';
  param_1[0x18] = '\0';
  param_1[0x19] = '\0';
  uVar2 = (**(code **)(*g_pLocalizationTable + 0x3c))();
  *(undefined2 *)(param_1 + 0x1a) = uVar2;
  param_1[0x4c] = '\0';
  pcVar7 = param_1 + 0x1e;
  for (iVar5 = 0xb; iVar5 != 0; iVar5 = iVar5 + -1) {
    pcVar7[0] = '\0';
    pcVar7[1] = '\0';
    pcVar7[2] = '\0';
    pcVar7[3] = '\0';
    pcVar7 = pcVar7 + 4;
  }
  pcVar7[0] = '\0';
  pcVar7[1] = '\0';
  return;
}

