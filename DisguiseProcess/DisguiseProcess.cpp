// Author: Alex zhang 2022/3/7.

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <iostream>

typedef NTSTATUS(WINAPI* PFUN_NtQueryInformationProcess)(
    _In_      HANDLE           ProcessHandle,
    _In_      PROCESSINFOCLASS ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
    );

DWORD GetProcessID(const wchar_t* window_name) {
    HWND hWinmine = FindWindowW(NULL, window_name);
    DWORD dwPID = 0;
    GetWindowThreadProcessId(hWinmine, &dwPID);
    if (dwPID == 0) {
        std::cout << "get pid failed!" << std::endl;
        return NULL;
    }
    return dwPID;
}

// Modify the PEB of a certain process(image path and command line) to
// disguise the process
BOOL DisguiseProcess(DWORD dwProcessId, wchar_t* lpwszPath, wchar_t* lpwszCmd) {
    HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    std::cout << dwProcessId << std::endl;
    if (NULL == hProcess) {
        return FALSE;
    }
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    PEB peb = { 0 };
    RTL_USER_PROCESS_PARAMETERS Param = { 0 };
    USHORT usCmdLen = 0;
    USHORT usPathLen = 0;

    // The needed Method is defined in ntdll.dll and we need to use LoadLibrary and GetProcessAddress to
    // fetch this method dynamiclly, see `https://docs.microsoft.com/en-us/windows/win32/api/winternl/
    // nf-winternl-ntqueryinformationprocess` for help.
    HMODULE hModule = LoadLibraryA("Ntdll.dll");
    PFUN_NtQueryInformationProcess pfun = (PFUN_NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
    if (NULL == pfun)
    {
        return FALSE;
    }
    // Get Information of the given process.
    NTSTATUS status = pfun(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    std::cout << GetLastError() << std::endl;

    // When reading/writing memory of other process.We should use ReadProcessMemory/WriteProcessMemory
    // instead of pointers beacause pointers are just locations pointing to the current process.

    ::ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
    ::ReadProcessMemory(hProcess, peb.ProcessParameters, &Param, sizeof(Param), NULL);

    usCmdLen = 2 + 2 * ::wcslen(lpwszCmd);
    ::WriteProcessMemory(hProcess, Param.CommandLine.Buffer, lpwszCmd, usCmdLen, NULL);
    ::WriteProcessMemory(hProcess, &Param.CommandLine.Length, &usCmdLen, sizeof(usCmdLen), NULL);

    usPathLen = 2 + 2 * ::wcslen(lpwszPath);
    ::WriteProcessMemory(hProcess, Param.ImagePathName.Buffer, lpwszPath, usPathLen, NULL);
    ::WriteProcessMemory(hProcess, &Param.ImagePathName.Length, &usPathLen, sizeof(usPathLen), NULL);
    return TRUE;
}
int main() {
    // You can use either window name or a given process ID.
    std::cout << "Input process ID." << std::endl;
    UINT32 processId;
    std::cin >> processId;
    wchar_t smz[10] = L"Explorer";
    wchar_t lpwszPath[30] = L"C:\\Windows\\explorer.exe";
    // DWORD processId = GetProcessID(L"Untitled - Notepad");

    if (FALSE == DisguiseProcess(processId, lpwszPath, smz)) {
        std::cout << "Dsisguise Process Error" << std::endl;
    }

    std::cout << "Dsisguise Process OK" << std::endl;
    system("pause");
    return 0;
}
