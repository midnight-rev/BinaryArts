#include <iostream>
#include <Windows.h>

// To compile: g++ -o .\APIHooking.exe .\APIHooking.cpp

LPVOID originalInitialBytes;

LPVOID setHook(uint32_t * functionToBeHooked, uint32_t * hookFunction) {
    // Allocating 5 bytes to save the original first 5 bytes of functionToBeHooked
    LPVOID originalPrologue = VirtualAlloc(NULL, 5, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!originalPrologue) return NULL;

    // Saving the value of first 5 bytes of functionToBeHooked to rollback the changes during execution
    memcpy(originalPrologue, functionToBeHooked, 5);

    // Updating virtual memory pages' permissions to allow writing
    DWORD lpflOldProtect;
    VirtualProtect((LPVOID)functionToBeHooked, 5, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
    
    char* ptr = (char *) functionToBeHooked;
    *ptr = 0xE9; // Writing JMP opcode to the start of the function
    int distanceToFunc = (int)hookFunction - (int)functionToBeHooked - 5; // Writing the value to relative jump to hookFunction
    memcpy(ptr + 1, &distanceToFunc, 4);

    VirtualProtect((LPVOID)functionToBeHooked, 5, lpflOldProtect, &lpflOldProtect); // Returning to function pages' original permissions
    return originalPrologue;
}

void unsetHook(uint32_t * hookedFunction, LPVOID originalPrologue) {
    DWORD lpflOldProtect;
    VirtualProtect((LPVOID)hookedFunction, 5, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
    memcpy(hookedFunction, originalPrologue, 5);
    VirtualProtect((LPVOID)hookedFunction, 5, lpflOldProtect, &lpflOldProtect);
}

int hookMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    // Unset the hook so the original function may be called
    unsetHook((uint32_t *)MessageBoxA, originalInitialBytes);

    // Hook instructions: do whatever you want from here, then execute MessageBoxA :)
    int toReturn = MessageBoxA(hWnd, "Hello From Hook :)", "This was hooked!", uType);

    // Set the hook again so further calls will call this hook function
    setHook((uint32_t *) MessageBoxA, (uint32_t *) hookMessageBoxA);
    return toReturn;
}

int main() {
    originalInitialBytes = setHook((uint32_t*) MessageBoxA, (uint32_t *)hookMessageBoxA);
    MessageBoxA(NULL, "I am trying to write this", "but I can't", 0x1);
}