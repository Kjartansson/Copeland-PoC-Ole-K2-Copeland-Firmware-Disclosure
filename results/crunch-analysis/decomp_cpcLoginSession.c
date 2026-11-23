
undefined4 cpcLoginSession(undefined4 param_1,int param_2,int param_3)

{
  char cVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 local_14;
  undefined1 local_d;
  
  if (((DAT_00ff6b40 != 0) && (param_2 != 0)) && (param_3 != 0)) {
    local_14 = 0;
    local_d = 0;
    cVar1 = GetUserData(param_2,param_3,&local_d,&local_14);
    if ((cVar1 != '\0') &&
       (iVar2 = _ZN14CpcSessionList11FindSessionEPc(DAT_00ff6b40,param_1), iVar2 != 0)) {
      *(undefined1 *)(iVar2 + 0x88) = local_d;
      _ZN10CpcSession11SetUsernameEPc(iVar2,param_2);
      *(undefined4 *)(iVar2 + 0x8c) = local_14;
      uVar3 = _ZN10CpcSession15GetCookieStringEv(iVar2);
      return uVar3;
    }
  }
  return 0;
}

