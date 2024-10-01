using System.Runtime.InteropServices;
using System;

namespace ImplantCryptor
{
  class Interop
  {
    ///////////////
    /// DInvoke ///
    ///////////////
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    public delegate IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, VIRTUAL_ALLOCATION_TYPE flAllocationType, PAGE_PROTECTION_FLAGS flProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    public delegate IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, VIRTUAL_ALLOCATION_TYPE flAllocationType, PAGE_PROTECTION_FLAGS flProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    public delegate IntPtr OpenProcess(PROCESS_ACCESS_RIGHTS processAccess,
        bool bInheritHandle, uint processId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    public delegate IntPtr CreateThread(ref SECURITY_ATTRIBUTES lpThreadAttributes,
        UIntPtr dwStackSize, ref IntPtr lpStartAddress, IntPtr lpParameter,
        UInt32 dwCreationFlags, out UInt32 lpThread);

    // cuz bool is not nullable
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    [return:MarshalAs(UnmanagedType.I1)]
    public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    [return:MarshalAs(UnmanagedType.I1)]
    public delegate bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
        UIntPtr dwSize, PAGE_PROTECTION_FLAGS flNewProtect, out PAGE_PROTECTION_FLAGS lpflOldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    public delegate NtStatus NtCreateThreadEx(out IntPtr hThread, ACCESS_MASK DesiredAccess, 
        IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, 
        IntPtr lpParameter, [MarshalAs(UnmanagedType.Bool)] bool CreateSuspended, 
        uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    public delegate NtStatus NtOpenProcess(ref IntPtr ProcessHandle, PROCESS_ACCESS_RIGHTS AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID clientId);


    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    public delegate NtStatus NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, VIRTUAL_ALLOCATION_TYPE allocationType, PAGE_PROTECTION_FLAGS protect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    public delegate NtStatus NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, uint bufferSize, out uint written);


    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    public delegate NtStatus ZwAllocateVirtualMemoryEx();
    //     IntPtr processHandle,
    //     _Inout_ _At_ (*BaseAddress, _Readable_bytes_ (*RegionSize) _Writable_bytes_ (*RegionSize) _Post_readable_byte_size_ (*RegionSize)) PVOID* BaseAddress,
    //     _Inout_ PSIZE_T RegionSize,
    //     _In_ ULONG AllocationType,
    //     _In_ ULONG PageProtection,
    //     _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    //     _In_ ULONG ExtendedParameterCount
    //     );

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    public delegate bool IsWow64Process([In] IntPtr hProcess, [Out] out bool lpSystemInfo);



    ///////////////
    /// PInvoke ///
    ///////////////
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetCurrentProcessId();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, WAIT_PROP dwMilliseconds);

    /////////////////
    /// CONSTANTS ///
    /////////////////
    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
      public IntPtr UniqueProcess;
      public IntPtr UniqueThread;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
      public int nLength;
      public IntPtr lpSecurityDescriptor;
      public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
      public int cb;
      public string lpReserved;
      public string lpDesktop;
      public string lpTitle;
      public int dwX;
      public int dwY;
      public int dwXSize;
      public int dwYSize;
      public int dwXCountChars;
      public int dwYCountChars;
      public int dwFillAttribute;
      public int dwFlags;
      public Int16 wShowWindow;
      public Int16 cbReserved2;
      public IntPtr lpReserved2;
      public IntPtr hStdInput;
      public IntPtr hStdOutput;
      public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
      public IntPtr hProcess;
      public IntPtr hThread;
      public int dwProcessId;
      public int dwThreadId;
    }

    [Flags]
    public enum ACCESS_MASK : uint
    {
      THREAD_ALL_ACCESS = 0x1FFFFF,

      DELETE = 0x00010000,
      READ_CONTROL = 0x00020000,
      WRITE_DAC = 0x00040000,
      WRITE_OWNER = 0x00080000,
      SYNCHRONIZE = 0x00100000,

      STANDARD_RIGHTS_REQUIRED = 0x000F0000,

      STANDARD_RIGHTS_READ = 0x00020000,
      STANDARD_RIGHTS_WRITE = 0x00020000,
      STANDARD_RIGHTS_EXECUTE = 0x00020000,

      STANDARD_RIGHTS_ALL = 0x001F0000,

      SPECIFIC_RIGHTS_ALL = 0x0000FFFF,

      ACCESS_SYSTEM_SECURITY = 0x01000000,

      MAXIMUM_ALLOWED = 0x02000000,

      GENERIC_READ = 0x80000000,
      GENERIC_WRITE = 0x40000000,
      GENERIC_EXECUTE = 0x20000000,
      GENERIC_ALL = 0x10000000,

      DESKTOP_READOBJECTS = 0x00000001,
      DESKTOP_CREATEWINDOW = 0x00000002,
      DESKTOP_CREATEMENU = 0x00000004,
      DESKTOP_HOOKCONTROL = 0x00000008,
      DESKTOP_JOURNALRECORD = 0x00000010,
      DESKTOP_JOURNALPLAYBACK = 0x00000020,
      DESKTOP_ENUMERATE = 0x00000040,
      DESKTOP_WRITEOBJECTS = 0x00000080,
      DESKTOP_SWITCHDESKTOP = 0x00000100,

      WINSTA_ENUMDESKTOPS = 0x00000001,
      WINSTA_READATTRIBUTES = 0x00000002,
      WINSTA_ACCESSCLIPBOARD = 0x00000004,
      WINSTA_CREATEDESKTOP = 0x00000008,
      WINSTA_WRITEATTRIBUTES = 0x00000010,
      WINSTA_ACCESSGLOBALATOMS = 0x00000020,
      WINSTA_EXITWINDOWS = 0x00000040,
      WINSTA_ENUMERATE = 0x00000100,
      WINSTA_READSCREEN = 0x00000200,

      WINSTA_ALL_ACCESS = 0x0000037F
    }

    [Flags]
    public enum VIRTUAL_ALLOCATION_TYPE : uint
    {
      MEM_COMMIT = 0x00001000,
      MEM_RESERVE = 0x00002000,
      MEM_RESET = 0x00080000,
      MEM_RESET_UNDO = 0x01000000,
      MEM_REPLACE_PLACEHOLDER = 0x00004000,
      MEM_LARGE_PAGES = 0x20000000,
      MEM_RESERVE_PLACEHOLDER = 0x00040000,
      MEM_FREE = 0x00010000,
    }

    [Flags]
    public enum MemoryProtection
    {
      Execute = 0x10,
      ExecuteRead = 0x20,
      ExecuteReadWrite = 0x40,
      ExecuteWriteCopy = 0x80,
      NoAccess = 0x01,
      ReadOnly = 0x02,
      ReadWrite = 0x04,
      WriteCopy = 0x08,
      GuardModifierflag = 0x100,
      NoCacheModifierflag = 0x200,
      WriteCombineModifierflag = 0x400
    }

    [Flags]
    public enum PAGE_PROTECTION_FLAGS : uint
    {
      PAGE_NOACCESS = 0x00000001,
      PAGE_READONLY = 0x00000002,
      PAGE_READWRITE = 0x00000004,
      PAGE_WRITECOPY = 0x00000008,
      PAGE_EXECUTE = 0x00000010,
      PAGE_EXECUTE_READ = 0x00000020,
      PAGE_EXECUTE_READWRITE = 0x00000040,
      PAGE_EXECUTE_WRITECOPY = 0x00000080,
      PAGE_GUARD = 0x00000100,
      PAGE_NOCACHE = 0x00000200,
      PAGE_WRITECOMBINE = 0x00000400,
      PAGE_GRAPHICS_NOACCESS = 0x00000800,
      PAGE_GRAPHICS_READONLY = 0x00001000,
      PAGE_GRAPHICS_READWRITE = 0x00002000,
      PAGE_GRAPHICS_EXECUTE = 0x00004000,
      PAGE_GRAPHICS_EXECUTE_READ = 0x00008000,
      PAGE_GRAPHICS_EXECUTE_READWRITE = 0x00010000,
      PAGE_GRAPHICS_COHERENT = 0x00020000,
      PAGE_GRAPHICS_NOCACHE = 0x00040000,
      PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000,
      PAGE_REVERT_TO_FILE_MAP = 0x80000000,
      PAGE_TARGETS_NO_UPDATE = 0x40000000,
      PAGE_TARGETS_INVALID = 0x40000000,
      PAGE_ENCLAVE_UNVALIDATED = 0x20000000,
      PAGE_ENCLAVE_MASK = 0x10000000,
      PAGE_ENCLAVE_DECOMMIT = 0x10000000,
      PAGE_ENCLAVE_SS_FIRST = 0x10000001,
      PAGE_ENCLAVE_SS_REST = 0x10000002,
      SEC_PARTITION_OWNER_HANDLE = 0x00040000,
      SEC_64K_PAGES = 0x00080000,
      SEC_FILE = 0x00800000,
      SEC_IMAGE = 0x01000000,
      SEC_PROTECTED_IMAGE = 0x02000000,
      SEC_RESERVE = 0x04000000,
      SEC_COMMIT = 0x08000000,
      SEC_NOCACHE = 0x10000000,
      SEC_WRITECOMBINE = 0x40000000,
      SEC_LARGE_PAGES = 0x80000000,
      SEC_IMAGE_NO_EXECUTE = 0x11000000,
    }

    [Flags]
    public enum PROCESS_ACCESS_RIGHTS : uint
    {
      PROCESS_TERMINATE = 0x00000001,
      PROCESS_CREATE_THREAD = 0x00000002,
      PROCESS_SET_SESSIONID = 0x00000004,
      PROCESS_VM_OPERATION = 0x00000008,
      PROCESS_VM_READ = 0x00000010,
      PROCESS_VM_WRITE = 0x00000020,
      PROCESS_DUP_HANDLE = 0x00000040,
      PROCESS_CREATE_PROCESS = 0x00000080,
      PROCESS_SET_QUOTA = 0x00000100,
      PROCESS_SET_INFORMATION = 0x00000200,
      PROCESS_QUERY_INFORMATION = 0x00000400,
      PROCESS_SUSPEND_RESUME = 0x00000800,
      PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,
      PROCESS_SET_LIMITED_INFORMATION = 0x00002000,
      PROCESS_ALL_ACCESS = 0x001FFFFF,
      PROCESS_DELETE = 0x00010000,
      PROCESS_READ_CONTROL = 0x00020000,
      PROCESS_WRITE_DAC = 0x00040000,
      PROCESS_WRITE_OWNER = 0x00080000,
      PROCESS_SYNCHRONIZE = 0x00100000,
      PROCESS_STANDARD_RIGHTS_REQUIRED = 0x000F0000,
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

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES : IDisposable
    {
      public int Length;
      public IntPtr RootDirectory;
      private IntPtr objectName;
      public uint Attributes;
      public IntPtr SecurityDescriptor;
      public IntPtr SecurityQualityOfService;

      public OBJECT_ATTRIBUTES(string name, uint attrs)
      {
        Length = 0;
        RootDirectory = IntPtr.Zero;
        objectName = IntPtr.Zero;
        Attributes = attrs;
        SecurityDescriptor = IntPtr.Zero;
        SecurityQualityOfService = IntPtr.Zero;

        Length = Marshal.SizeOf(this);
        ObjectName = new UNICODE_STRING(name);
      }

      public UNICODE_STRING ObjectName
      {
        get
        {
          return (UNICODE_STRING)Marshal.PtrToStructure(
              objectName, typeof(UNICODE_STRING));
        }

        set
        {
          bool fDeleteOld = objectName != IntPtr.Zero;
          if (!fDeleteOld)
            objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
          Marshal.StructureToPtr(value, objectName, fDeleteOld);
        }
      }

      public void Dispose()
      {
        if (objectName != IntPtr.Zero)
        {
          Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
          Marshal.FreeHGlobal(objectName);
          objectName = IntPtr.Zero;
        }
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

    public enum WAIT_PROP : uint
    {
      INFINITE = 0xFFFFFFFF,
      WAIT_ABANDONED = 0x00000080,
      WAIT_OBJECT_0 = 0x00000000,
      WAIT_TIMEOUT = 0x00000102
    }

  }
}
