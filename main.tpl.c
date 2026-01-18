#include <windows.h>

int main(int argc, char ** argv)
// int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
    int bytecode_size = SET_SIZE; //récupération de la taille du bytecode
    unsigned char bytecode[SET_SIZE] = {SET_BYTECODE}; // récupération du bytecode
    DWORD dummy;

    VirtualProtect(bytecode, bytecode_size,
                PAGE_EXECUTE_READWRITE, &dummy);

    // cast en fonction
    void (*function)(void) = (void (*)(void))bytecode;
    
    // appel de la fonction
    function();
}