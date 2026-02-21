
void __fastcall FUN_004dbf00(int *param_1)

{
  code *pcVar1;
  uint uVar2;
  uint uVar3;
  char cVar4;
  short sVar5;
  short sVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  undefined4 unaff_EBP;
  int iVar11;
  int *piVar12;
  uint uStack_84;
  int *piStack_80;
  short *local_7c;
  int iStack_78;
  int iStack_74;
  int *piStack_6c;
  int aiStack_60 [4];
  int iStack_50;
  int iStack_48;
  
  iVar11 = 1;
  iVar7 = (**(code **)(*(int *)param_1[0x24] + 0x28))();
  if (0 < iVar7) {
    do {
      uVar2 = uStack_84;
      uStack_84 = uStack_84 & 0xffffff;
      uVar3 = uStack_84;
      iVar11 = (**(code **)(*(int *)param_1[0x24] + 0x24))(iVar11);
      iVar7 = g_pGlobalMapState[4] + iVar11 * 0xa8;
      if ((int)*(short *)(iVar7 + 4) != param_1[0x22]) {
        sVar5 = (**(code **)(*g_pLocalizationTable + 0x3c))();
        uVar8 = (int)sVar5 - (int)*(short *)(iVar7 + 6);
        uStack_84 = uVar2 & 0xffff00;
        if (4 < (int)uVar8) {
          iStack_78 = 0;
          piVar12 = aiStack_60;
          for (iVar10 = 0x17; iVar10 != 0; iVar10 = iVar10 + -1) {
            *piVar12 = 0;
            piVar12 = piVar12 + 1;
          }
          if ('\0' < *(char *)(iVar7 + 0x3a)) {
            local_7c = (short *)(iVar7 + 0x42);
            do {
              iVar10 = 0;
              sVar5 = *local_7c;
              do {
                sVar6 = (short)*(char *)(g_pGlobalMapState[3] + (int)(short)iVar10 + 0x11 +
                                        sVar5 * 0x24);
                if (sVar6 != -1) {
                  cVar4 = (**(code **)(*g_pGlobalMapState + 0xc4))(sVar5,iVar10);
                  aiStack_60[sVar6] = aiStack_60[sVar6] + (int)cVar4;
                }
                iVar10 = iVar10 + 1;
              } while (iVar10 < 2);
              local_7c = local_7c + 1;
              iStack_78 = iStack_78 + 1;
              param_1 = piStack_6c;
            } while (iStack_78 < *(char *)(iVar7 + 0x3a));
          }
          if ((uVar8 & 1) == 0) {
            sVar5 = (short)aiStack_60[0] + (short)aiStack_60[1];
            if (sVar5 != 0) {
              iVar10 = GetCityBuildingProductionValueBySlot(piStack_80,1);
              sVar6 = *(short *)(iVar7 + 0x84);
              if ((sVar6 < (short)((int)((int)(short)iVar10 + ((int)(short)iVar10 >> 0x1f & 3U)) >>
                                  2)) && ((int)sVar6 < (int)sVar5 / 2)) {
                uStack_84._1_3_ = SUB43(uVar3,1);
                uStack_84 = CONCAT31(uStack_84._1_3_,1);
                *(short *)(iVar7 + 0x84) = sVar6 + 1;
                unaff_EBP = 0x1000000;
              }
            }
            iVar10 = aiStack_60[2];
            if (aiStack_60[2] != 0) {
              iVar9 = GetCityBuildingProductionValueBySlot(piStack_80,5);
              sVar5 = *(short *)(iVar7 + 0x86);
              if ((sVar5 < (short)((int)((int)(short)iVar9 + ((int)(short)iVar9 >> 0x1f & 3U)) >> 2)
                  ) && ((int)sVar5 < iVar10 / 2)) {
                uStack_84 = CONCAT31(uStack_84._1_3_,1);
                *(short *)(iVar7 + 0x86) = sVar5 + 1;
                unaff_EBP = 0x1000000;
              }
            }
            if ((aiStack_60[3] != 0) && (iStack_50 != 0)) {
              iVar10 = aiStack_60[3];
              if (iStack_50 <= aiStack_60[3]) {
                iVar10 = iStack_50;
              }
              iVar9 = GetCityBuildingProductionValueBySlot(piStack_80,3);
              sVar5 = *(short *)(iVar7 + 0x8a);
              if ((sVar5 < (short)((int)((int)(short)iVar9 + ((int)(short)iVar9 >> 0x1f & 3U)) >> 2)
                  ) && ((int)sVar5 < (int)(short)iVar10 / 2)) {
                uStack_84 = CONCAT31(uStack_84._1_3_,1);
                *(short *)(iVar7 + 0x8a) = sVar5 + 1;
                unaff_EBP = 0x1000000;
              }
            }
            if (((iStack_48 != 0) && (*(char *)(g_pCityOrderCapabilityState + 0x193) != '\0')) &&
               ((int)*(short *)(iVar7 + 0x8c) < iStack_48 / 2)) {
              uStack_84 = CONCAT31(uStack_84._1_3_,1);
              *(short *)(iVar7 + 0x8c) = *(short *)(iVar7 + 0x8c) + 1;
              unaff_EBP = 0x1000000;
            }
          }
          if ((9 < (int)uVar8 & (byte)uVar8) != 0) {
            (**(code **)(*piStack_80 + 0x74))();
            if ((*(short *)(iVar7 + 0x84) != 0) &&
               ((int)*(short *)(iVar7 + 0x8e) < (int)*(short *)(iVar7 + 0x84) / 2)) {
              uStack_84 = CONCAT31(uStack_84._1_3_,2);
              *(short *)(iVar7 + 0x8e) = *(short *)(iVar7 + 0x8e) + 1;
              unaff_EBP = 0x1000000;
            }
            if ((*(short *)(iVar7 + 0x86) != 0) &&
               ((int)*(short *)(iVar7 + 0x90) < (int)*(short *)(iVar7 + 0x86) / 2)) {
              uStack_84 = CONCAT31(uStack_84._1_3_,2);
              *(short *)(iVar7 + 0x90) = *(short *)(iVar7 + 0x90) + 1;
              unaff_EBP = 0x1000000;
            }
            if ((*(short *)(iVar7 + 0x8a) != 0) &&
               ((int)*(short *)(iVar7 + 0x92) < (int)*(short *)(iVar7 + 0x8a) / 2)) {
              uStack_84 = CONCAT31(uStack_84._1_3_,2);
              *(short *)(iVar7 + 0x92) = *(short *)(iVar7 + 0x92) + 1;
              unaff_EBP = 0x1000000;
            }
          }
          if (*(char *)(g_pGlobalMapState[4] + 2 + (short)iVar11 * 0xa8) < (char)uStack_84) {
            thunk_FUN_00518960(iVar11,uStack_84);
            if ((char)uStack_84 == '\x02') {
              (**(code **)(*param_1 + 0xb8))(4,iVar11);
            }
            else {
              pcVar1 = *(code **)(*param_1 + 0xb8);
              (*pcVar1)(3,iVar11);
              if ((char)param_1[0x234] < '3') {
                (*pcVar1)(8,0xffffffff);
              }
            }
          }
        }
        if ((g_pLocalizationTable[0x11] != 0) && ((char)((uint)unaff_EBP >> 0x18) != '\0')) {
          DispatchCityRedrawInvalidateEvent((short)iVar11);
        }
      }
      iVar11 = iStack_74 + 1;
      iVar7 = (**(code **)(*(int *)param_1[0x24] + 0x28))();
      iStack_74 = iVar11;
    } while (iVar11 <= iVar7);
  }
  return;
}

