using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;

class Program
{
    // Import necessary Windows API functions
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool CloseHandle(IntPtr handle);

    // Constants for process access and memory allocation
    const uint PROCESS_VM_OPERATION = 0x0008;
    const uint PROCESS_VM_WRITE = 0x0020;
    const uint PROCESS_VM_READ = 0x0010;
    const uint PROCESS_CREATE_THREAD = 0x0002;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;

    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_READWRITE = 0x04;

    static void SetConsoleColor(ConsoleColor color)
    {
        Console.ForegroundColor = color;
    }

    static void Main()
    {
       // place ur damn path to ur dlll (or js rename placeholder.dll if they are in the same directory.)
        string dllPath = Path.GetFullPath(@".\placeholder.dll");

    
        if (!File.Exists(dllPath))
        {
            SetConsoleColor(ConsoleColor.Red);
            Console.WriteLine($"DLL file not found at {dllPath}");
            Console.WriteLine("Restart application. Make sure dll file is correct. [Press Insert to exit]");
            WaitForExit(); // Exit immediately
            return;
        }

       
        Process[] robloxProcesses = Process.GetProcessesByName("RobloxPlayerBeta");
        if (robloxProcesses.Length == 0)
        {
            SetConsoleColor(ConsoleColor.Red);
            Console.WriteLine("Process 'RobloxPlayerBeta' not found.");
            WaitForExit();
            return;
        }

        Process targetProcess = robloxProcesses[0];
        SetConsoleColor(ConsoleColor.White);
        Console.WriteLine("Process 'RobloxPlayerBeta' found. Initializing Injection...");

        uint desiredAccess = PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;
        IntPtr hProcess = OpenProcess(desiredAccess, false, targetProcess.Id);
        if (hProcess == IntPtr.Zero)
        {
            SetConsoleColor(ConsoleColor.Red);
            Console.WriteLine($"Failed to open target process. Error code: {Marshal.GetLastWin32Error()}");
            WaitForExit();
            return;
        }

        SetConsoleColor(ConsoleColor.DarkBlue);
        Console.WriteLine("Access to process granted.");

        IntPtr allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)Encoding.Default.GetByteCount(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (allocMemAddress == IntPtr.Zero)
        {
            SetConsoleColor(ConsoleColor.Red);
            Console.WriteLine($"Memory allocation failed. Error code: {Marshal.GetLastWin32Error()}");
            CloseHandle(hProcess);
            WaitForExit();
            return;
        }

        SetConsoleColor(ConsoleColor.Yellow);
        Console.WriteLine("Memory allocated in target process.");

        byte[] dllBytes = Encoding.Default.GetBytes(dllPath);
        if (!WriteProcessMemory(hProcess, allocMemAddress, dllBytes, (uint)dllBytes.Length, out _))
        {
            SetConsoleColor(ConsoleColor.Red);
            Console.WriteLine($"Failed to write DLL path to memory. Error code: {Marshal.GetLastWin32Error()}");
            CloseHandle(hProcess);
            WaitForExit();
            return;
        }

        SetConsoleColor(ConsoleColor.Cyan);
        Console.WriteLine("DLL path written to memory.");

        IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        if (loadLibraryAddr == IntPtr.Zero)
        {
            SetConsoleColor(ConsoleColor.Red);
            Console.WriteLine($"Failed to find LoadLibraryA. Error code: {Marshal.GetLastWin32Error()}");
            CloseHandle(hProcess);
            WaitForExit();
            return;
        }

        IntPtr remoteThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
        if (remoteThread == IntPtr.Zero)
        {
            SetConsoleColor(ConsoleColor.Red);
            Console.WriteLine($"Failed to create remote thread. Error code: {Marshal.GetLastWin32Error()}");
            CloseHandle(hProcess);
            WaitForExit();
            return;
        }

        SetConsoleColor(ConsoleColor.Green);
        Console.WriteLine("Remote thread created. DLL Injection initiated.");

        CloseHandle(hProcess);

        SetConsoleColor(ConsoleColor.Green);
        Console.WriteLine("DLL Injected Successfully Into RobloxPlayerBeta.");
        SetConsoleColor(ConsoleColor.White);

        Console.WriteLine("Press Insert to exit...");

        WaitForExit(); 
    }

  
    static void WaitForExit()
    {
        while (Console.ReadKey(true).Key != ConsoleKey.Insert) { }
        Environment.Exit(0);
    }
}
