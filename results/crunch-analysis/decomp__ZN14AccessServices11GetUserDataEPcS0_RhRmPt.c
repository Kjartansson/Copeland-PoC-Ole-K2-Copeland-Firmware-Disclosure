
undefined4
_ZN14AccessServices11GetUserDataEPcS0_RhRmPt
          (int param_1,char *param_2,undefined4 param_3,undefined1 *param_4,undefined4 *param_5,
          undefined2 *param_6)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined2 local_34 [4];
  undefined2 local_2c [6];
  undefined1 local_1f;
  undefined4 local_1e;
  undefined2 local_1a;
  undefined1 local_18 [2];
  undefined1 local_16;
  undefined1 local_15;
  
  if ((param_2 == (char *)0x0) || (*param_2 == '\0')) {
    *param_4 = 0;
    *param_5 = 0;
    return 0;
  }
  iVar1 = stricmp(s_ONEDAY_00cce2d8,param_2);
  if (iVar1 == 0) {
    local_1e = 0;
    local_1a = 0;
    local_1f = DAT_00cce28c;
    FUN_0089a8c0();
    iVar1 = stricmp(param_3,&local_1f);
    if (iVar1 == 0) {
      *param_4 = 5;
      *param_5 = 0x708;
      if (param_6 == (undefined2 *)0x0) {
        return 1;
      }
      *param_6 = 0;
      return 1;
    }
  }
  else {
    iVar1 = stricmp(&DAT_00cce2df,param_2);
    if (iVar1 == 0) {
      local_1e = 0;
      local_1a = 0;
      local_1f = DAT_00cce28c;
      _ZN12TimeServices17GetDateTimeStructEv(local_2c,DAT_00fec7d4);
      _Z12JulianToDatetP15SNVT_date_cal_X(local_2c[0],local_18);
      _ZN14AccessServices20CalculateSalPasswordEhhhPc(param_1,local_16,local_15,1,&local_1f);
      iVar1 = stricmp(param_3,&local_1f);
      if (iVar1 == 0) {
        *param_4 = 5;
        *param_5 = 0x708;
        if (param_6 == (undefined2 *)0x0) {
          return 1;
        }
        *param_6 = 0;
        return 1;
      }
    }
    else {
      iVar3 = 0;
      iVar1 = stricmp(&DAT_00cce2e3,param_2);
      if (iVar1 == 0) {
        local_1e = 0;
        local_1a = 0;
        local_1f = DAT_00cce28c;
        _ZN12TimeServices17GetDateTimeStructEv(local_34,DAT_00fec7d4);
        _Z12JulianToDatetP15SNVT_date_cal_X(local_34[0],local_18);
        _ZN14AccessServices20CalculateSalPasswordEhhhPc(param_1,local_16,local_15,0,&local_1f);
        iVar1 = stricmp(param_3,&local_1f);
        if (iVar1 == 0) {
          *param_4 = 0;
          *param_5 = 0x708;
          return 1;
        }
      }
      else {
        do {
          iVar1 = iVar3 * 0x1e;
          iVar2 = stricmp(param_2,iVar1 + 0xd4 + param_1);
          if ((iVar2 == 0) && (iVar2 = stricmp(param_3,iVar1 + 0xe4 + param_1), iVar2 == 0)) {
            iVar1 = iVar1 + 0xe0 + param_1;
            *param_4 = *(undefined1 *)(iVar1 + 0xf);
            *param_5 = *(undefined4 *)(iVar1 + 0xb);
            if (param_6 == (undefined2 *)0x0) {
              return 1;
            }
            *param_6 = *(undefined2 *)(param_1 + 0x3d8 + iVar3 * 2);
            return 1;
          }
          iVar3 = iVar3 + 1;
        } while (iVar3 != 0x19);
      }
    }
  }
  return 0;
}

