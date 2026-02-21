
void FUN_00563da0(void)

{
  char cVar1;
  short sVar2;
  uint uVar3;
  int *piVar4;
  void *pCurrentPortZone;
  int iVar5;
  int local_c;
  int local_8;
  int local_4;
  
  local_c = 0;
  local_8 = 0;
  do {
    cVar1 = *(char *)(*(int *)(g_pGlobalMapState + 0xc) + 0x16 + local_8);
    if ((cVar1 == '\x03') || (cVar1 == '\x0e')) {
      for (pCurrentPortZone = GetFirstPortZone(); pCurrentPortZone != (void *)0x0;
          pCurrentPortZone = GetNextPortZone(pCurrentPortZone)) {
        sVar2 = (short)local_c;
        if (((*(short *)((int)pCurrentPortZone + 0xc) == sVar2) ||
            (*(short *)((int)pCurrentPortZone + 0x20) == sVar2)) ||
           (*(short *)((int)pCurrentPortZone + 0x48) == sVar2)) goto LAB_00563e22;
      }
      pCurrentPortZone = (void *)0x0;
    }
    else {
      sVar2 = (short)*(char *)(*(int *)(g_pGlobalMapState + 0xc) + local_8 + 4);
      if (sVar2 < 0x17) {
        pCurrentPortZone = (void *)0x0;
      }
      else {
        pCurrentPortZone = (void *)(*(int *)(g_pActiveMapContextState + 8) + (sVar2 + -0x17) * 0x48)
        ;
      }
    }
LAB_00563e22:
    if (pCurrentPortZone != (void *)0x0) {
      local_4 = 0;
      do {
        sVar2 = thunk_StepHexTileIndexByDirectionWithWrapRules(local_c,local_4);
        if (sVar2 != -1) {
          sVar2 = *(short *)(*(int *)(g_pGlobalMapState + 0xc) + 0x14 + sVar2 * 0x24);
          if (sVar2 == -1) {
            iVar5 = 0;
          }
          else {
            iVar5 = *(int *)(g_pGlobalMapState + 0x10) + sVar2 * 0xa8;
          }
          if (iVar5 != 0) {
            uVar3 = 0;
            if (*(uint *)((int)pCurrentPortZone + 0x40) != 0) {
              piVar4 = *(int **)((int)pCurrentPortZone + 0x38);
              do {
                if (*piVar4 == iVar5) {
                  piVar4 = *(int **)((int)pCurrentPortZone + 0x38) + uVar3;
                  goto LAB_00563e98;
                }
                uVar3 = uVar3 + 1;
                piVar4 = piVar4 + 1;
              } while (uVar3 < *(uint *)((int)pCurrentPortZone + 0x40));
            }
            piVar4 = (int *)0x0;
LAB_00563e98:
            if (piVar4 == (int *)0x0) {
              (*(code *)**(undefined4 **)((int)pCurrentPortZone + 0x34))(iVar5);
            }
          }
        }
        local_4 = local_4 + 1;
      } while (local_4 < 6);
    }
    local_c = local_c + 1;
    local_8 = local_8 + 0x24;
    if (0x194f < (short)local_c) {
      return;
    }
  } while( true );
}

