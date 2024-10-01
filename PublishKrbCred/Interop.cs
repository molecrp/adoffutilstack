using System.Runtime.InteropServices;
using System.Security.Principal;
using System;

namespace PublishKrbCred
{
  public class Interop
  {
    ////////////////
    /// SECURITY ///
    ////////////////
    public enum SECURITY_IMPERSONATION_LEVEL
    {
      SecurityAnonymous,
      SecurityIdentification,
      SecurityImpersonation,
      SecurityDelegation
    }

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool ImpersonateSelf(SECURITY_IMPERSONATION_LEVEL ImpersonationLevel);

    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle,
        TOKEN_ACCESS_RIGHTS DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool LookupAccountSid(
        [MarshalAs(UnmanagedType.LPTStr)] string strSystemName,
        IntPtr pSid,
        IntPtr pName,
        ref uint cchName,
        IntPtr pReferencedDomainName,
        ref uint cchReferencedDomainName,
        out SID_NAME_USE peUse);

    // Use this signature if you do not want the previous state
    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
        [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        UInt32 Zero,
        IntPtr Null1,
        IntPtr Null2);

    [DllImport("advapi32.dll", SetLastError=true)]
    public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int
        SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

    [DllImport("Secur32.dll", SetLastError = false)]
    public static extern NtStatus LsaEnumerateLogonSessions(out uint LogonSessionCount, out IntPtr LogonSessionList);

    [DllImport("secur32.dll", SetLastError = false)]
    public static extern uint LsaFreeReturnBuffer(
        IntPtr buffer
        );

    [DllImport("Secur32.dll", SetLastError = false)]
    public static extern uint LsaGetLogonSessionData(
        IntPtr luid,
        out IntPtr ppLogonSessionData
        );

    [DllImport("secur32.dll", SetLastError = true)]
    public static extern NtStatus LsaRegisterLogonProcess(
        LSA_STRING LogonProcessName,
        out IntPtr LsaHandle,
        out ulong SecurityMode
        );

    [DllImport("secur32.dll", SetLastError = false)]
    public static extern NtStatus LsaLookupAuthenticationPackage(
        [In] IntPtr LsaHandle,
        [In] ref LSA_STRING PackageName,
        [Out] out int AuthenticationPackage
        );


    [DllImport("secur32.dll", SetLastError = false)]
    public static extern int LsaConnectUntrusted(
        [Out] out IntPtr LsaHandle
        );

    // [DllImport("SECUR32.dll", ExactSpelling = true)]
    // [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    // public static extern unsafe NTSTATUS LsaCallAuthenticationPackage(
    //     HANDLE LsaHandle,
    //     uint AuthenticationPackage,
    //     void* ProtocolSubmitBuffer,
    //     uint SubmitBufferLength,
    //     [Optional] void** ProtocolReturnBuffer,
    //     [Optional] uint* ReturnBufferLength,
    //     [Optional] int* ProtocolStatus);
    [DllImport("Secur32.dll", SetLastError = true)]
    internal static extern NtStatus LsaCallAuthenticationPackage(
        IntPtr LsaHandle,
        int AuthenticationPackage,
        IntPtr ProtocolSubmitBuffer,
        int SubmitBufferLength,
        out IntPtr ProtocolReturnBuffer,
        out int ReturnBufferLength,
        out int ProtocolStatus
        );

    [DllImport("secur32.dll", SetLastError = false)]
    public static extern int LsaDeregisterLogonProcess(
        [In] IntPtr LsaHandle
        );

    public struct KERB_SUBMIT_TKT_REQUEST
    {
      public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
      public LUID LogonId;
      public int Flags;
      public KERB_CRYPTO_KEY32 Key; // key to decrypt KERB_CRED
      public int KerbCredSize;
      public int KerbCredOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_CRYPTO_KEY32
    {
      public int KeyType;
      public int Length;
      public int Offset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_RETRIEVE_TKT_RESPONSE
    {
      public KERB_EXTERNAL_TICKET Ticket;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_EXTERNAL_TICKET
    {
      public IntPtr ServiceName;
      public IntPtr TargetName;
      public IntPtr ClientName;
      public LSA_STRING_OUT DomainName;
      public LSA_STRING_OUT TargetDomainName;
      public LSA_STRING_OUT AltTargetDomainName;
      public KERB_CRYPTO_KEY SessionKey;
      public UInt32 TicketFlags;
      public UInt32 Flags;
      public Int64 KeyExpirationTime;
      public Int64 StartTime;
      public Int64 EndTime;
      public Int64 RenewUntil;
      public Int64 TimeSkew;
      public Int32 EncodedTicketSize;
      public IntPtr EncodedTicket;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_CRYPTO_KEY
    {
      public Int32 KeyType;
      public Int32 Length;
      public IntPtr Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_RETRIEVE_TKT_REQUEST
    {
      public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
      public LUID LogonId;
      public UNICODE_STRING TargetName;
      public UInt32 TicketFlags;
      public UInt32 CacheOptions;
      public Int32 EncryptionType;
      public SECURITY_HANDLE CredentialsHandle;
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_HANDLE
    {
      public IntPtr LowPart;
      public IntPtr HighPart;
      public SECURITY_HANDLE(int dummy)
      {
        LowPart = HighPart = IntPtr.Zero;
      }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING : IDisposable
    {
      public ushort Length;
      public ushort MaximumLength;
      public IntPtr buffer;

      public UNICODE_STRING(string s)
      {
        Length = (ushort)(s.Length * 2);
        MaximumLength = (ushort)(Length + 2);
        buffer = Marshal.StringToHGlobalUni(s);
      }

      public void Dispose()
      {
        Marshal.FreeHGlobal(buffer);
        buffer = IntPtr.Zero;
      }

      public override string ToString()
      {
        return Marshal.PtrToStringUni(buffer);
      }
    }

    public enum KERB_PROTOCOL_MESSAGE_TYPE : UInt32
    {
      KerbDebugRequestMessage = 0,
      KerbQueryTicketCacheMessage = 1,
      KerbChangeMachinePasswordMessage = 2,
      KerbVerifyPacMessage = 3,
      KerbRetrieveTicketMessage = 4,
      KerbUpdateAddressesMessage = 5,
      KerbPurgeTicketCacheMessage = 6,
      KerbChangePasswordMessage = 7,
      KerbRetrieveEncodedTicketMessage = 8,
      KerbDecryptDataMessage = 9,
      KerbAddBindingCacheEntryMessage = 10,
      KerbSetPasswordMessage = 11,
      KerbSetPasswordExMessage = 12,
      KerbVerifyCredentialsMessage = 13,
      KerbQueryTicketCacheExMessage = 14,
      KerbPurgeTicketCacheExMessage = 15,
      KerbRefreshSmartcardCredentialsMessage = 16,
      KerbAddExtraCredentialsMessage = 17,
      KerbQuerySupplementalCredentialsMessage = 18,
      KerbTransferCredentialsMessage = 19,
      KerbQueryTicketCacheEx2Message = 20,
      KerbSubmitTicketMessage = 21,
      KerbAddExtraCredentialsExMessage = 22,
      KerbQueryKdcProxyCacheMessage = 23,
      KerbPurgeKdcProxyCacheMessage = 24,
      KerbQueryTicketCacheEx3Message = 25,
      KerbCleanupMachinePkinitCredsMessage = 26,
      KerbAddBindingCacheEntryExMessage = 27,
      KerbQueryBindingCacheMessage = 28,
      KerbPurgeBindingCacheMessage = 29,
      KerbQueryDomainExtendedPoliciesMessage = 30,
      KerbQueryS4U2ProxyCacheMessage = 31
    }

    /////////////////
    /// THREADING ///
    /////////////////
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenThreadToken(
        IntPtr ThreadHandle,
        TOKEN_ACCESS_RIGHTS DesiredAccess,
        bool OpenAsSelf,
        out IntPtr TokenHandle);

    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentThread();

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        TOKEN_INFORMATION_CLASS TokenInformationClass,
        out TOKEN_STATISTICS TokenInformation,
        int TokenInformationLength,
        out int ReturnLength);

    [DllImport("advapi32.dll")]
    public static extern bool LookupPrivilegeValue(string lpSystemName, 
        string lpName, ref LUID lpLuid);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern uint LsaNtStatusToWinError(uint status);


    //////////////
    /// MEMORY ///
    //////////////
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle([In] IntPtr hObject);

    [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
    public static extern void CopyMemory(IntPtr dest, IntPtr src, uint count);

    /////////////////////
    /// ENUMS/STRUCTS ///
    ///////////////////// 
    public enum LogonType : uint
    {
      Interactive = 2,        // logging on interactively.
      Network,                // logging using a network.
      Batch,                  // logon for a batch process.
      Service,                // logon for a service account.
      Proxy,                  // Not supported.
      Unlock,                 // Tattempt to unlock a workstation.
      NetworkCleartext,       // network logon with cleartext credentials
      NewCredentials,         // caller can clone its current token and specify new credentials for outbound connections
      RemoteInteractive,      // terminal server session that is both remote and interactive
      CachedInteractive,      // attempt to use the cached credentials without going out across the network
      CachedRemoteInteractive,// same as RemoteInteractive, except used internally for auditing purposes
      CachedUnlock            // attempt to unlock a workstation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_LOGON_SESSION_DATA
    {
      public UInt32 Size;
      public LUID LoginID;
      public LSA_STRING_OUT Username;
      public LSA_STRING_OUT LoginDomain;
      public LSA_STRING_OUT AuthenticationPackage;
      public UInt32 LogonType;
      public UInt32 Session;
      public IntPtr PSiD;
      public UInt64 LoginTime;
      public LSA_STRING_OUT LogonServer;
      public LSA_STRING_OUT DnsDomainName;
      public LSA_STRING_OUT Upn;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING_OUT
    {
      public UInt16 Length;
      public UInt16 MaximumLength;
      public IntPtr Buffer;
    }

    public struct LSA_UNICODE_STRING
    {
      public UInt16 Length;
      public UInt16 MaximumLength;
      public IntPtr buffer;
    }

    public class LogonSessionData
    {
      public LUID LogonID;
      public string Username;
      public string LogonDomain;
      public string AuthenticationPackage;
      public LogonType LogonType;
      public int Session;
      public SecurityIdentifier Sid;
      public DateTime LogonTime;
      public string LogonServer;
      public string DnsDomainName;
      public string Upn;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING
    {
      public UInt16 Length;
      public UInt16 MaximumLength;
      public /*PCHAR*/ string Buffer;
    }

    public enum SID_NAME_USE
    {
      SidTypeUser = 1,
      SidTypeGroup,
      SidTypeDomain,
      SidTypeAlias,
      SidTypeWellKnownGroup,
      SidTypeDeletedAccount,
      SidTypeInvalid,
      SidTypeUnknown,
      SidTypeComputer
    }

    public enum TOKEN_INFORMATION_CLASS
    {
      TokenUser = 1,
      TokenGroups, // 2
      TokenPrivileges, // 3
      TokenOwner, // ...
      TokenPrimaryGroup,
      TokenDefaultDacl,
      TokenSource,
      TokenType,
      TokenImpersonationLevel,
      TokenStatistics,
      TokenRestrictedSids,
      TokenSessionId,
      TokenGroupsAndPrivileges,
      TokenSessionReference,
      TokenSandBoxInert,
      TokenAuditPolicy,
      TokenOrigin
    }

    public struct TOKEN_USER
    {
      public SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {

      public IntPtr Sid;
      public int Attributes;
    }



    // [StructLayout(LayoutKind.Sequential)]
    // public struct LUID {
    //   public uint LowPart;
    //   public uint HighPart;
    // }

    public struct TOKEN_PRIVILEGES
    {
      public uint PrivilegeCount;
      public LUID_AND_ATTRIBUTES Privileges;
    }

    public struct LUID_AND_ATTRIBUTES
    {
      public LUID Luid;
      public TOKEN_PRIVILEGES_ATTRIBUTES Attributes;
    }

    [Flags]
    public enum TOKEN_PRIVILEGES_ATTRIBUTES : uint
    {
      SE_PRIVILEGE_ENABLED = 0x00000002,
      SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
      SE_PRIVILEGE_REMOVED = 0x00000004,
      SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000,
    }


    [Flags]
    public enum SnapshotFlags : uint
    {
      HeapList = 0x00000001,
      Process = 0x00000002,
      Thread = 0x00000004,
      Module = 0x00000008,
      Module32 = 0x00000010,
      Inherit = 0x80000000,
      All = 0x0000001F,
      NoHeaps = 0x40000000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    internal struct PROCESSENTRY32
    {
      const int MAX_PATH = 260;
      internal UInt32 dwSize;
      internal UInt32 cntUsage;
      internal UInt32 th32ProcessID;
      internal IntPtr th32DefaultHeapID;
      internal UInt32 th32ModuleID;
      internal UInt32 cntThreads;
      internal UInt32 th32ParentProcessID;
      internal Int32 pcPriClassBase;
      internal UInt32 dwFlags;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
      internal string szExeFile;
    }

    [Flags]
    public enum TOKEN_ACCESS_RIGHTS : uint
    {
      STANDARD_RIGHTS_REQUIRED = 0x000F0000,
      STANDARD_RIGHTS_READ = 0x00020000,
      TOKEN_ASSIGN_PRIMARY = 0x0001,
      TOKEN_DUPLICATE = 0x0002,
      TOKEN_IMPERSONATE = 0x0004,
      TOKEN_QUERY = 0x0008,
      TOKEN_QUERY_SOURCE = 0x0010,
      TOKEN_ADJUST_PRIVILEGES = 0x0020,
      TOKEN_ADJUST_GROUPS = 0x0040,
      TOKEN_ADJUST_DEFAULT = 0x0080,
      TOKEN_ADJUST_SESSIONID = 0x0100,
      TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
          TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
          TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
          TOKEN_ADJUST_SESSIONID)
    }

    public struct TOKEN_STATISTICS
    {
      public LUID TokenId;
      public LUID AuthenticationId;
      public long ExpirationTime;
      public TOKEN_TYPE TokenType;
      public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
      public uint DynamicCharged;
      public uint DynamicAvailable;
      public uint GroupCount;
      public uint PrivilegeCount;
      public LUID ModifiedId;
    }

    public enum TOKEN_TYPE
    {
      TokenPrimary = 1,
      TokenImpersonation = 2,
    }

    public enum NtStatus : uint
    {
      // Success
      Success = 0x00000000,
      Wait0 = 0x00000000,
      Wait1 = 0x00000001,
      Wait2 = 0x00000002,
      Wait3 = 0x00000003,
      Wait63 = 0x0000003f,
      Abandoned = 0x00000080,
      AbandonedWait0 = 0x00000080,
      AbandonedWait1 = 0x00000081,
      AbandonedWait2 = 0x00000082,
      AbandonedWait3 = 0x00000083,
      AbandonedWait63 = 0x000000bf,
      UserApc = 0x000000c0,
      KernelApc = 0x00000100,
      Alerted = 0x00000101,
      Timeout = 0x00000102,
      Pending = 0x00000103,
      Reparse = 0x00000104,
      MoreEntries = 0x00000105,
      NotAllAssigned = 0x00000106,
      SomeNotMapped = 0x00000107,
      OpLockBreakInProgress = 0x00000108,
      VolumeMounted = 0x00000109,
      RxActCommitted = 0x0000010a,
      NotifyCleanup = 0x0000010b,
      NotifyEnumDir = 0x0000010c,
      NoQuotasForAccount = 0x0000010d,
      PrimaryTransportConnectFailed = 0x0000010e,
      PageFaultTransition = 0x00000110,
      PageFaultDemandZero = 0x00000111,
      PageFaultCopyOnWrite = 0x00000112,
      PageFaultGuardPage = 0x00000113,
      PageFaultPagingFile = 0x00000114,
      CrashDump = 0x00000116,
      ReparseObject = 0x00000118,
      NothingToTerminate = 0x00000122,
      ProcessNotInJob = 0x00000123,
      ProcessInJob = 0x00000124,
      ProcessCloned = 0x00000129,
      FileLockedWithOnlyReaders = 0x0000012a,
      FileLockedWithWriters = 0x0000012b,

      // Informational
      Informational = 0x40000000,
      ObjectNameExists = 0x40000000,
      ThreadWasSuspended = 0x40000001,
      WorkingSetLimitRange = 0x40000002,
      ImageNotAtBase = 0x40000003,
      RegistryRecovered = 0x40000009,

      // Warning
      Warning = 0x80000000,
      GuardPageViolation = 0x80000001,
      DatatypeMisalignment = 0x80000002,
      Breakpoint = 0x80000003,
      SingleStep = 0x80000004,
      BufferOverflow = 0x80000005,
      NoMoreFiles = 0x80000006,
      HandlesClosed = 0x8000000a,
      PartialCopy = 0x8000000d,
      DeviceBusy = 0x80000011,
      InvalidEaName = 0x80000013,
      EaListInconsistent = 0x80000014,
      NoMoreEntries = 0x8000001a,
      LongJump = 0x80000026,
      DllMightBeInsecure = 0x8000002b,

      // Error
      Error = 0xc0000000,
      Unsuccessful = 0xc0000001,
      NotImplemented = 0xc0000002,
      InvalidInfoClass = 0xc0000003,
      InfoLengthMismatch = 0xc0000004,
      AccessViolation = 0xc0000005,
      InPageError = 0xc0000006,
      PagefileQuota = 0xc0000007,
      InvalidHandle = 0xc0000008,
      BadInitialStack = 0xc0000009,
      BadInitialPc = 0xc000000a,
      InvalidCid = 0xc000000b,
      TimerNotCanceled = 0xc000000c,
      InvalidParameter = 0xc000000d,
      NoSuchDevice = 0xc000000e,
      NoSuchFile = 0xc000000f,
      InvalidDeviceRequest = 0xc0000010,
      EndOfFile = 0xc0000011,
      WrongVolume = 0xc0000012,
      NoMediaInDevice = 0xc0000013,
      NoMemory = 0xc0000017,
      NotMappedView = 0xc0000019,
      UnableToFreeVm = 0xc000001a,
      UnableToDeleteSection = 0xc000001b,
      IllegalInstruction = 0xc000001d,
      AlreadyCommitted = 0xc0000021,
      AccessDenied = 0xc0000022,
      BufferTooSmall = 0xc0000023,
      ObjectTypeMismatch = 0xc0000024,
      NonContinuableException = 0xc0000025,
      BadStack = 0xc0000028,
      NotLocked = 0xc000002a,
      NotCommitted = 0xc000002d,
      InvalidParameterMix = 0xc0000030,
      ObjectNameInvalid = 0xc0000033,
      ObjectNameNotFound = 0xc0000034,
      ObjectNameCollision = 0xc0000035,
      ObjectPathInvalid = 0xc0000039,
      ObjectPathNotFound = 0xc000003a,
      ObjectPathSyntaxBad = 0xc000003b,
      DataOverrun = 0xc000003c,
      DataLate = 0xc000003d,
      DataError = 0xc000003e,
      CrcError = 0xc000003f,
      SectionTooBig = 0xc0000040,
      PortConnectionRefused = 0xc0000041,
      InvalidPortHandle = 0xc0000042,
      SharingViolation = 0xc0000043,
      QuotaExceeded = 0xc0000044,
      InvalidPageProtection = 0xc0000045,
      MutantNotOwned = 0xc0000046,
      SemaphoreLimitExceeded = 0xc0000047,
      PortAlreadySet = 0xc0000048,
      SectionNotImage = 0xc0000049,
      SuspendCountExceeded = 0xc000004a,
      ThreadIsTerminating = 0xc000004b,
      BadWorkingSetLimit = 0xc000004c,
      IncompatibleFileMap = 0xc000004d,
      SectionProtection = 0xc000004e,
      EasNotSupported = 0xc000004f,
      EaTooLarge = 0xc0000050,
      NonExistentEaEntry = 0xc0000051,
      NoEasOnFile = 0xc0000052,
      EaCorruptError = 0xc0000053,
      FileLockConflict = 0xc0000054,
      LockNotGranted = 0xc0000055,
      DeletePending = 0xc0000056,
      CtlFileNotSupported = 0xc0000057,
      UnknownRevision = 0xc0000058,
      RevisionMismatch = 0xc0000059,
      InvalidOwner = 0xc000005a,
      InvalidPrimaryGroup = 0xc000005b,
      NoImpersonationToken = 0xc000005c,
      CantDisableMandatory = 0xc000005d,
      NoLogonServers = 0xc000005e,
      NoSuchLogonSession = 0xc000005f,
      NoSuchPrivilege = 0xc0000060,
      PrivilegeNotHeld = 0xc0000061,
      InvalidAccountName = 0xc0000062,
      UserExists = 0xc0000063,
      NoSuchUser = 0xc0000064,
      GroupExists = 0xc0000065,
      NoSuchGroup = 0xc0000066,
      MemberInGroup = 0xc0000067,
      MemberNotInGroup = 0xc0000068,
      LastAdmin = 0xc0000069,
      WrongPassword = 0xc000006a,
      IllFormedPassword = 0xc000006b,
      PasswordRestriction = 0xc000006c,
      LogonFailure = 0xc000006d,
      AccountRestriction = 0xc000006e,
      InvalidLogonHours = 0xc000006f,
      InvalidWorkstation = 0xc0000070,
      PasswordExpired = 0xc0000071,
      AccountDisabled = 0xc0000072,
      NoneMapped = 0xc0000073,
      TooManyLuidsRequested = 0xc0000074,
      LuidsExhausted = 0xc0000075,
      InvalidSubAuthority = 0xc0000076,
      InvalidAcl = 0xc0000077,
      InvalidSid = 0xc0000078,
      InvalidSecurityDescr = 0xc0000079,
      ProcedureNotFound = 0xc000007a,
      InvalidImageFormat = 0xc000007b,
      NoToken = 0xc000007c,
      BadInheritanceAcl = 0xc000007d,
      RangeNotLocked = 0xc000007e,
      DiskFull = 0xc000007f,
      ServerDisabled = 0xc0000080,
      ServerNotDisabled = 0xc0000081,
      TooManyGuidsRequested = 0xc0000082,
      GuidsExhausted = 0xc0000083,
      InvalidIdAuthority = 0xc0000084,
      AgentsExhausted = 0xc0000085,
      InvalidVolumeLabel = 0xc0000086,
      SectionNotExtended = 0xc0000087,
      NotMappedData = 0xc0000088,
      ResourceDataNotFound = 0xc0000089,
      ResourceTypeNotFound = 0xc000008a,
      ResourceNameNotFound = 0xc000008b,
      ArrayBoundsExceeded = 0xc000008c,
      FloatDenormalOperand = 0xc000008d,
      FloatDivideByZero = 0xc000008e,
      FloatInexactResult = 0xc000008f,
      FloatInvalidOperation = 0xc0000090,
      FloatOverflow = 0xc0000091,
      FloatStackCheck = 0xc0000092,
      FloatUnderflow = 0xc0000093,
      IntegerDivideByZero = 0xc0000094,
      IntegerOverflow = 0xc0000095,
      PrivilegedInstruction = 0xc0000096,
      TooManyPagingFiles = 0xc0000097,
      FileInvalid = 0xc0000098,
      InstanceNotAvailable = 0xc00000ab,
      PipeNotAvailable = 0xc00000ac,
      InvalidPipeState = 0xc00000ad,
      PipeBusy = 0xc00000ae,
      IllegalFunction = 0xc00000af,
      PipeDisconnected = 0xc00000b0,
      PipeClosing = 0xc00000b1,
      PipeConnected = 0xc00000b2,
      PipeListening = 0xc00000b3,
      InvalidReadMode = 0xc00000b4,
      IoTimeout = 0xc00000b5,
      FileForcedClosed = 0xc00000b6,
      ProfilingNotStarted = 0xc00000b7,
      ProfilingNotStopped = 0xc00000b8,
      NotSameDevice = 0xc00000d4,
      FileRenamed = 0xc00000d5,
      CantWait = 0xc00000d8,
      PipeEmpty = 0xc00000d9,
      CantTerminateSelf = 0xc00000db,
      InternalError = 0xc00000e5,
      InvalidParameter1 = 0xc00000ef,
      InvalidParameter2 = 0xc00000f0,
      InvalidParameter3 = 0xc00000f1,
      InvalidParameter4 = 0xc00000f2,
      InvalidParameter5 = 0xc00000f3,
      InvalidParameter6 = 0xc00000f4,
      InvalidParameter7 = 0xc00000f5,
      InvalidParameter8 = 0xc00000f6,
      InvalidParameter9 = 0xc00000f7,
      InvalidParameter10 = 0xc00000f8,
      InvalidParameter11 = 0xc00000f9,
      InvalidParameter12 = 0xc00000fa,
      MappedFileSizeZero = 0xc000011e,
      TooManyOpenedFiles = 0xc000011f,
      Cancelled = 0xc0000120,
      CannotDelete = 0xc0000121,
      InvalidComputerName = 0xc0000122,
      FileDeleted = 0xc0000123,
      SpecialAccount = 0xc0000124,
      SpecialGroup = 0xc0000125,
      SpecialUser = 0xc0000126,
      MembersPrimaryGroup = 0xc0000127,
      FileClosed = 0xc0000128,
      TooManyThreads = 0xc0000129,
      ThreadNotInProcess = 0xc000012a,
      TokenAlreadyInUse = 0xc000012b,
      PagefileQuotaExceeded = 0xc000012c,
      CommitmentLimit = 0xc000012d,
      InvalidImageLeFormat = 0xc000012e,
      InvalidImageNotMz = 0xc000012f,
      InvalidImageProtect = 0xc0000130,
      InvalidImageWin16 = 0xc0000131,
      LogonServer = 0xc0000132,
      DifferenceAtDc = 0xc0000133,
      SynchronizationRequired = 0xc0000134,
      DllNotFound = 0xc0000135,
      IoPrivilegeFailed = 0xc0000137,
      OrdinalNotFound = 0xc0000138,
      EntryPointNotFound = 0xc0000139,
      ControlCExit = 0xc000013a,
      PortNotSet = 0xc0000353,
      DebuggerInactive = 0xc0000354,
      CallbackBypass = 0xc0000503,
      PortClosed = 0xc0000700,
      MessageLost = 0xc0000701,
      InvalidMessage = 0xc0000702,
      RequestCanceled = 0xc0000703,
      RecursiveDispatch = 0xc0000704,
      LpcReceiveBufferExpected = 0xc0000705,
      LpcInvalidConnectionUsage = 0xc0000706,
      LpcRequestsNotAllowed = 0xc0000707,
      ResourceInUse = 0xc0000708,
      ProcessIsProtected = 0xc0000712,
      VolumeDirty = 0xc0000806,
      FileCheckedOut = 0xc0000901,
      CheckOutRequired = 0xc0000902,
      BadFileType = 0xc0000903,
      FileTooLarge = 0xc0000904,
      FormsAuthRequired = 0xc0000905,
      VirusInfected = 0xc0000906,
      VirusDeleted = 0xc0000907,
      TransactionalConflict = 0xc0190001,
      InvalidTransaction = 0xc0190002,
      TransactionNotActive = 0xc0190003,
      TmInitializationFailed = 0xc0190004,
      RmNotActive = 0xc0190005,
      RmMetadataCorrupt = 0xc0190006,
      TransactionNotJoined = 0xc0190007,
      DirectoryNotRm = 0xc0190008,
      CouldNotResizeLog = 0xc0190009,
      TransactionsUnsupportedRemote = 0xc019000a,
      LogResizeInvalidSize = 0xc019000b,
      RemoteFileVersionMismatch = 0xc019000c,
      CrmProtocolAlreadyExists = 0xc019000f,
      TransactionPropagationFailed = 0xc0190010,
      CrmProtocolNotFound = 0xc0190011,
      TransactionSuperiorExists = 0xc0190012,
      TransactionRequestNotValid = 0xc0190013,
      TransactionNotRequested = 0xc0190014,
      TransactionAlreadyAborted = 0xc0190015,
      TransactionAlreadyCommitted = 0xc0190016,
      TransactionInvalidMarshallBuffer = 0xc0190017,
      CurrentTransactionNotValid = 0xc0190018,
      LogGrowthFailed = 0xc0190019,
      ObjectNoLongerExists = 0xc0190021,
      StreamMiniversionNotFound = 0xc0190022,
      StreamMiniversionNotValid = 0xc0190023,
      MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
      CantOpenMiniversionWithModifyIntent = 0xc0190025,
      CantCreateMoreStreamMiniversions = 0xc0190026,
      HandleNoLongerValid = 0xc0190028,
      NoTxfMetadata = 0xc0190029,
      LogCorruptionDetected = 0xc0190030,
      CantRecoverWithHandleOpen = 0xc0190031,
      RmDisconnected = 0xc0190032,
      EnlistmentNotSuperior = 0xc0190033,
      RecoveryNotNeeded = 0xc0190034,
      RmAlreadyStarted = 0xc0190035,
      FileIdentityNotPersistent = 0xc0190036,
      CantBreakTransactionalDependency = 0xc0190037,
      CantCrossRmBoundary = 0xc0190038,
      TxfDirNotEmpty = 0xc0190039,
      IndoubtTransactionsExist = 0xc019003a,
      TmVolatile = 0xc019003b,
      RollbackTimerExpired = 0xc019003c,
      TxfAttributeCorrupt = 0xc019003d,
      EfsNotAllowedInTransaction = 0xc019003e,
      TransactionalOpenNotAllowed = 0xc019003f,
      TransactedMappingUnsupportedRemote = 0xc0190040,
      TxfMetadataAlreadyPresent = 0xc0190041,
      TransactionScopeCallbacksNotSet = 0xc0190042,
      TransactionRequiredPromotion = 0xc0190043,
      CannotExecuteFileInTransaction = 0xc0190044,
      TransactionsNotFrozen = 0xc0190045,

      MaximumNtStatus = 0xffffffff
    }

    public enum KERB_ETYPE : Int32
    {
      des_cbc_crc = 1,
      des_cbc_md4 = 2,
      des_cbc_md5 = 3,
      des3_cbc_md5 = 5,
      des3_cbc_sha1 = 7,
      dsaWithSHA1_CmsOID = 9,
      md5WithRSAEncryption_CmsOID = 10,
      sha1WithRSAEncryption_CmsOID = 11,
      rc2CBC_EnvOID = 12,
      rsaEncryption_EnvOID = 13,
      rsaES_OAEP_ENV_OID = 14,
      des_ede3_cbc_Env_OID = 15,
      des3_cbc_sha1_kd = 16,
      aes128_cts_hmac_sha1 = 17,
      aes256_cts_hmac_sha1 = 18,
      rc4_hmac = 23,
      rc4_hmac_exp = 24,
      subkey_keymaterial = 65,
      old_exp = -135
    }

    [Flags]
    public enum KERB_CACHE_OPTIONS : uint
    {
      KERB_RETRIEVE_TICKET_DEFAULT = 0x0,
      KERB_RETRIEVE_TICKET_DONT_USE_CACHE = 0x1,
      KERB_RETRIEVE_TICKET_USE_CACHE_ONLY = 0x2,
      KERB_RETRIEVE_TICKET_USE_CREDHANDLE = 0x4,
      KERB_RETRIEVE_TICKET_AS_KERB_CRED = 0x8,
      KERB_RETRIEVE_TICKET_WITH_SEC_CRED = 0x10,
      KERB_RETRIEVE_TICKET_CACHE_TICKET = 0x20,
      KERB_RETRIEVE_TICKET_MAX_LIFETIME = 0x40,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
      public UInt32 LowPart;
      public Int32 HighPart;

      public LUID(UInt64 value)
      {
        LowPart = (UInt32)(value & 0xffffffffL);
        HighPart = (Int32)(value >> 32);
      }

      public LUID(LUID value)
      {
        LowPart = value.LowPart;
        HighPart = value.HighPart;
      }

      public LUID(string value)
      {
        if (System.Text.RegularExpressions.Regex.IsMatch(value, @"^0x[0-9A-Fa-f]+$"))
        {
          // if the passed LUID string is of form 0xABC123
          UInt64 uintVal = Convert.ToUInt64(value, 16);
          LowPart = (UInt32)(uintVal & 0xffffffffL);
          HighPart = (Int32)(uintVal >> 32);
        }
        else if (System.Text.RegularExpressions.Regex.IsMatch(value, @"^\d+$"))
        {
          // if the passed LUID string is a decimal form
          UInt64 uintVal = UInt64.Parse(value);
          LowPart = (UInt32)(uintVal & 0xffffffffL);
          HighPart = (Int32)(uintVal >> 32);
        }
        else
        {
          System.ArgumentException argEx = new System.ArgumentException("Passed LUID string value is not in a hex or decimal form", value);
          throw argEx;
        }
      }

      public override int GetHashCode()
      {
        UInt64 Value = ((UInt64)this.HighPart << 32) + this.LowPart;
        return Value.GetHashCode();
      }

      public override bool Equals(object obj)
      {
        return obj is LUID && (((ulong)this) == (LUID)obj);
      }

      public override string ToString()
      {
        UInt64 Value = ((UInt64)this.HighPart << 32) + this.LowPart;
        return String.Format("0x{0:x}", (ulong)Value);
      }

      public static bool operator ==(LUID x, LUID y)
      {
        return (((ulong)x) == ((ulong)y));
      }

      public static bool operator !=(LUID x, LUID y)
      {
        return (((ulong)x) != ((ulong)y));
      }

      public static implicit operator ulong(LUID luid)
      {
        // enable casting to a ulong
        UInt64 Value = ((UInt64)luid.HighPart << 32);
        return Value + luid.LowPart;
      }
    }
  }
}
