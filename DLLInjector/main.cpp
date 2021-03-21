#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>

// DLL Injector

int wmain(int argc, wchar_t * argv[]) {
	if (argc < 3) {
		std::wcerr << "USAGE: " << argv[0] << " <path_to_dll> <process_name>" << std::endl;
		return 1;
	}

	// Declaration of Variables
	HANDLE hProcess, hSnapshot;
	PROCESSENTRY32 procEntry;
	LPVOID DllRemoteLocation;
	SIZE_T lpNumberOfBytesWritten;

	// 1 - Get the process with the name equal to argv[2]

	std::wcout << "[+] Trying to get list of active processes..." << std::endl;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnapshot) {
		std::wcerr << "[-] Error on snapshoting processes." << std::endl;
		return 1;
	}

	procEntry.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &procEntry)) {
		do {
			if (!lstrcmpW(argv[2], procEntry.szExeFile)) {
				std::wcout << "[+] Process name: " << procEntry.szExeFile << " | PID: " << procEntry.th32ProcessID << std::endl;
				break;
			}
		} while (Process32Next(hSnapshot, &procEntry));
	}

	// Close Snapshot handle
	CloseHandle(hSnapshot);

	// 2 - Open the remote process

	std::wcout << "[+] Opening process " << procEntry.szExeFile << "..." << std::endl;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, procEntry.th32ProcessID);
	if (!hProcess) {
		std::wcerr << "[-] Error opening process." << std::endl;
		return 1;
	}

	// 3 - Alocate memory in remote process

	std::wcout << "[+] Allocating memory in the remote process..." << std::endl;

	DllRemoteLocation = VirtualAllocEx(hProcess, 0, 0xFF, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!DllRemoteLocation) {
		std::wcerr << "[-] Error in allocating remote memory." << std::endl;
		CloseHandle(hProcess);
		return 1;
	}

	// 4 - Write DLL name in remote process

	std::wcout << "[+] Writing DLL Name to remote process memory..." << std::endl;

	BOOL status = WriteProcessMemory(hProcess, DllRemoteLocation, argv[1], 2 * (lstrlenW(argv[1]) + 1), &lpNumberOfBytesWritten);
	if (!status) {
		std::wcerr << "[-] Error writing remote process memory" << std::endl;
		VirtualFreeEx(hProcess, DllRemoteLocation, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return 1;
	}

	std::wcout << "[+] DLL written to 0x" << std::hex << DllRemoteLocation << std::endl;

	// 5 - Get a pointer to LoadLibraryW and create a remote thread using this pointer as entry point
	DWORD threadId;

	HANDLE hLoadLibrary = GetProcAddress(GetModuleHandle(L"KERNEL32.DLL"), "LoadLibraryW");
	if (hLoadLibrary == INVALID_HANDLE_VALUE) {
		std::wcerr << "[-] Error getting handle for LoadLibraryW" << std::endl;
		VirtualFreeEx(hProcess, DllRemoteLocation, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return 1;
	}

	std::wcout << "[+] Creating remote thread..." << std::endl;

	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) hLoadLibrary, DllRemoteLocation, CREATE_SUSPENDED, &threadId);

	if (!hRemoteThread) {
		std::wcerr << "[-] Error creating suspended remote thread" << std::endl;
		VirtualFreeEx(hProcess, DllRemoteLocation, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		CloseHandle(hLoadLibrary);
		return 1;
	}

	std::wcout << "[+] Created remote thread " << std::hex << threadId << std::endl;
	std::wcout << "[+] Injection successful" << std::endl;

	ResumeThread(hRemoteThread);
	WaitForSingleObject(hRemoteThread, 5000);

	VirtualFreeEx(hProcess, DllRemoteLocation, 0, MEM_RELEASE);
	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);
	CloseHandle(hLoadLibrary);
}