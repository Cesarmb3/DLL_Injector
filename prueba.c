#include <windows.h>
//estructura para los argumentos del messagebox
typedef struct _INJECTION_ARGS {
    PVOID pMessageBoxA;
    char szTexto[128];
    char szTitulo[64];
} INJECTION_ARGS, *PINJECTION_ARGS;

//nuevo tipo de dato para invocar la funcion de alertas de windows MessageBoxA de forma dinámica
typedef int(WINAPI* FN_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

//declaracion de la funcion de carga
__declspec(dllexport) void ReflectiveLoader(PINJECTION_ARGS pArgs) {
    //validar punteros
    if (!pArgs || !pArgs->pMessageBoxA) return;
    //toma la dir en memoria que el inyector le pasa en la estructura y la asigna a la variable del principio
    FN_MessageBoxA pMessageBoxA = (FN_MessageBoxA)pArgs->pMessageBoxA;

    //ejecutamos el message box
    pMessageBoxA(
        NULL,
        pArgs->szTexto,
        pArgs->szTitulo,
        MB_OK | MB_ICONINFORMATION
    );
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    return TRUE;
}