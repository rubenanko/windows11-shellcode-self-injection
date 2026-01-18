
int main(int argc, char ** argv)
{
    int bytecode_size = SET_SIZE; //récupération de la taille du bytecode
    unsigned char bytecode[SET_SIZE] = {SET_BYTECODE}; // récupération du bytecode
    
    // cast en fonction
    void (*function)(void) = (void (*)(void))bytecode;
    
    // appel de la fonction
    function();
}