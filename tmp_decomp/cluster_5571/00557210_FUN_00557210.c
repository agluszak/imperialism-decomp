
void __thiscall FUN_00557210(int param_1,short param_2)

{
  int *piVar1;
  int *piVar2;
  int *piVar3;
  
  piVar2 = g_pNavySecondaryOrderList;
  if ((g_pNavyPrimaryOrderList != (int *)0x0) &&
     (piVar3 = g_pNavyPrimaryOrderList, g_pNavyPrimaryOrderList != (int *)0x0)) {
LAB_00557228:
    do {
      piVar1 = piVar3;
      if ((short)piVar3[5] == param_2) {
        piVar1 = (int *)piVar3[9];
        (**(code **)(*piVar3 + 0x1c))();
        piVar3 = piVar1;
        if (piVar1 != (int *)0x0) goto LAB_00557228;
      }
      piVar2 = g_pNavySecondaryOrderList;
      if ((piVar1 == (int *)0x0) || (piVar3 = (int *)piVar1[9], piVar3 == (int *)0x0)) break;
    } while( true );
  }
  do {
    if (piVar2 == (int *)0x0) {
LAB_00557270:
      piVar2 = *(int **)(param_1 + 4);
      do {
        if (piVar2 == (int *)0x0) {
          return;
        }
        do {
          piVar3 = piVar2;
          if ((short)piVar2[7] != param_2) break;
          piVar3 = (int *)piVar2[0xb];
          (**(code **)(*piVar2 + 0x1c))();
          piVar2 = piVar3;
        } while (piVar3 != (int *)0x0);
        if (piVar3 == (int *)0x0) {
          return;
        }
        piVar2 = (int *)piVar3[0xb];
      } while( true );
    }
    do {
      piVar3 = piVar2;
      if ((short)piVar2[1] != param_2) break;
      piVar3 = (int *)piVar2[5];
      (**(code **)(*piVar2 + 0x1c))();
      piVar2 = piVar3;
    } while (piVar3 != (int *)0x0);
    if (piVar3 == (int *)0x0) goto LAB_00557270;
    piVar2 = (int *)piVar3[5];
  } while( true );
}

