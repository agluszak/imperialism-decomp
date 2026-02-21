
void FUN_00562f20(void)

{
  ushort *puVar1;
  char cVar2;
  bool bVar3;
  short sVar4;
  short sVar5;
  undefined2 uVar6;
  void *pvVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  undefined4 uVar12;
  int iStack_c;
  
  for (piVar9 = g_pMapActionContextListHead; piVar9 != (int *)0x0; piVar9 = (int *)piVar9[6]) {
    *(undefined2 *)(piVar9 + 4) = 0;
  }
  pvVar7 = thunk_GetNavyPrimaryOrderListHead();
  iVar11 = g_pGlobalMapState;
  for (; g_pGlobalMapState = iVar11, pvVar7 != (void *)0x0; pvVar7 = *(void **)((int)pvVar7 + 0x24))
  {
    puVar1 = (ushort *)(*(int *)((int)pvVar7 + 8) + 0x10);
    *puVar1 = *puVar1 | (ushort)(1 << (*(byte *)((int)pvVar7 + 0x14) & 0x1f));
    iVar11 = g_pGlobalMapState;
  }
  iVar8 = 0;
  iVar10 = 0;
  do {
    cVar2 = *(char *)(*(int *)(iVar11 + 0xc) + 0x16 + iVar10);
    if ((cVar2 < '\a') || ('\r' < cVar2)) {
      bVar3 = false;
    }
    else {
      bVar3 = true;
    }
    if (bVar3) {
      iVar11 = -1;
LAB_00562fa2:
      thunk_FUN_00515e00(iVar8,iVar11);
      iVar11 = g_pGlobalMapState;
    }
    else {
      if ((cVar2 < '\x0e') || ('\x15' < cVar2)) {
        bVar3 = false;
      }
      else {
        bVar3 = true;
      }
      if (bVar3) {
        iVar11 = -CONCAT22((short)((uint)*(int *)(iVar11 + 0xc) >> 0x10),(short)cVar2);
        goto LAB_00562fa2;
      }
    }
    iVar8 = iVar8 + 1;
    iVar10 = iVar10 + 0x24;
    if (0x194f < (short)iVar8) {
      sVar4 = thunk_GetActiveNationId();
      if (g_pMapActionContextListHead != (int *)0x0) {
        piVar9 = g_pMapActionContextListHead;
        do {
          if (((*(byte *)(piVar9 + 4) & '\x01' << ((byte)sVar4 & 0x1f)) != 0) ||
             (bVar3 = thunk_ContainsPointerArrayEntryMatchingByteKey(), bVar3)) {
            bVar3 = true;
          }
          else {
            bVar3 = false;
          }
          if (bVar3) {
            iVar11 = *piVar9;
            uVar12 = 1;
            sVar5 = thunk_GetActiveNationId(1);
            uVar12 = CanDisplayMapOrderEntryInCurrentContext((int)sVar5,uVar12);
            (**(code **)(iVar11 + 0x58))(uVar12);
            iStack_c = 6;
            iVar8 = (int)sVar4;
            do {
              iVar8 = iVar8 + 1;
              if ((*(byte *)(piVar9 + 4) & '\x01' << ((byte)(iVar8 % 7) & 0x1f)) != 0) {
                uVar12 = (**(code **)(iVar11 + 0x50))();
                thunk_FUN_00515e00(uVar12,iVar8 % 7 + 7);
                *(undefined2 *)(*(int *)(g_pGlobalMapState + 0xc) + 0x1a + (short)uVar12 * 0x24) =
                     0xffff;
              }
              iStack_c = iStack_c + -1;
            } while (iStack_c != 0);
          }
          piVar9 = (int *)piVar9[6];
        } while (piVar9 != (int *)0x0);
      }
      for (iVar11 = *(int *)(g_pNavyOrderManager + 4); iVar11 != 0; iVar11 = *(int *)(iVar11 + 0x2c)
          ) {
        sVar4 = *(short *)(iVar11 + 0x1c);
        sVar5 = thunk_GetActiveNationId();
        if ((sVar4 != sVar5) && (*(int *)(iVar11 + 8) == 5)) {
          iVar8 = thunk_GetCityIndexFromCityStatePointer(*(int *)(iVar11 + 0xc));
          sVar4 = thunk_GetActiveNationId();
          if (*(char *)(*(int *)(g_pGlobalMapState + 0x10) + iVar8 * 0xa8) == sVar4) {
            sVar4 = (**(code **)(**(int **)(iVar11 + 0x18) + 0x54))(*(undefined4 *)(iVar11 + 0xc));
            if (sVar4 != -1) {
              thunk_FUN_00515e00((int)sVar4,*(short *)(iVar11 + 0x1c) + 7);
              uVar6 = thunk_GetNavyOrderRankWithinNationBucket();
              *(undefined2 *)(*(int *)(g_pGlobalMapState + 0xc) + 0x1a + sVar4 * 0x24) = uVar6;
            }
          }
        }
      }
      return;
    }
  } while( true );
}

