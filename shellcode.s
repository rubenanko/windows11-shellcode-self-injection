BITS 64

section .text
global _start

_start:
  ; alignement de la stack
  and rsp, -0x10

  ; obtention de l'adresse de base de kernel32.dll
  ; -> obtention de la liste des modules
  xor rax, rax
  mov rax, gs:[0x60] ; PEB
  mov rax, [rax + 0x18] ; PEB_LDR_DATA
  add rax, 0x20 ; InMemoryOrderModuleList

  test rax, rax
  jz exit_error

  ; parcours de la liste des modules
  mov rcx, rax ; entée de la liste
  lea rdx, [rel str_caps_kernel32] ; module cible
  mov rax, [rax] ; premier module

.loop_through_modules:
    cmp rax, rcx
    je exit_error ; module introuvable
    mov rdi, [rax + 0x50] ; pointeur vers le nom du module

.chrcmp:
    mov sil, [rdi]
    mov bl, [rdx]
    cmp sil, bl
    jne .next_module
    test sil, sil
    jz .module_trouve
    add rdi, 2
    inc rdx
    jmp .chrcmp

.next_module:
    lea rdx, [rel str_caps_kernel32] ; module cible
    mov rax, [rax] ; module suivant
    jmp .loop_through_modules
    
.module_trouve:
  mov rax, [rax + 0x20] ; base du dll
  mov [rel addr_kernel32base], rax 

  ; récupération du header PE
  mov rdi, rax
  mov eax, [rdi + 0x3C] ; offset header PE
  add rax, rdi ; adresse du header PE
  
  ; vérification des magic bytes
  cmp dword [rax], 0x00004550
  jne exit_error

  ; récupération de l'export directory
  ; 0x88 = 0x18 (offset des headers optionnel dans le header) + 0x70 (offset des headers optionnels)
  mov eax, [rax + 0x88]
  test rax, rax ; on vérifie que l'offset est non nul
  jz exit_error
 
  add rax,rdi
  mov [rel addr_ExportDirectory], rax
  
  ; récupération de l'addresse de GetModuleHandleA
  lea rcx, [rel str_GetModuleHandleA]
  call get_function_address
  test rax, rax
  jz exit_error
  mov [rel addr_GetModuleHandleA], rax

  ; récupération de l'addresse de GetProcAddressA
  lea rcx, [rel str_GetProcAddress]
  call get_function_address
  test rax, rax
  jz exit_error
  mov [rel addr_GetProcAddressA], rax

  ; appel de MessageBoxA
  ; -> chargement du module user32 avec l'api
  ;   -> résolution de l'adresse de LoadLibraryA avec l'api
  lea rcx, [rel str_kernel32]
  call [rel addr_GetModuleHandleA]
  mov rcx, rax  ; handle
  lea rdx, [rel str_LoadLibraryA] ; fonction cible
  call [rel addr_GetProcAddressA]
  
  ; appel de LoadLibraryA
  lea rcx, [rel str_user32] ; module cible "USER32"
  call rax ; LoadLibraryA

  mov rcx, rax ; handle user32.dll
  lea rdx, [rel str_MessageBoxA] ; fonction cible
  call [rel addr_GetProcAddressA] 

  xor rcx, rcx ; window handle
  xor r9, r9 ; type default
  lea r8, [rel str_title] ; titre
  lea rdx, [rel str_text] ; contenu textuel
  call rax

  ; appel de ExitThread
  lea rcx, [rel str_kernel32] ; module cible
  call [rel addr_GetModuleHandleA]
  mov rcx, rax ; handle
  lea rdx, [rel str_ExitThread] ; fonction cible
  call [rel addr_GetProcAddressA]

  xor rcx,rcx ; ExitThread(0)
  call rax

exit_error:
    ud2 ; undefined instruction -> provoque une erreur

; fonction qui compare deux chaines de caractères et retourne 0 si égalité
streq:
    push rcx
    push rdx
.streq_loop:
    mov al, BYTE [rcx]
    cmp al,BYTE[rdx]
    jne .not_equal
    test al,al
    jz .equal
    inc rcx
    inc rdx
    jmp .streq_loop

.equal:
    pop rdx
    pop rcx
    xor rax,rax
    ret

.not_equal:
    pop rdx
    pop rcx
    mov rax,1
    ret

; rcx -> pointeur vers nom de la fonction cible X
; retourne l'adresse de la fonction X
get_function_address:

  ; initialisation des registres
  mov rdx, [rel addr_kernel32base]
  mov r8, rcx     
  mov r9, [rel addr_ExportDirectory]
  
  mov ecx,  [r9 + 0x18] ; NumberOfNames -> nombre de symboles exportés
  mov r10d, [r9 + 0x20] ; offset AddressOfNames
  add r10, rdx ; AddressOfNames

; itération sur les symboles exportés
.loop_through_symbols:
  jecxz .fonction_introuvable ; check rcx = 0
  dec rcx

  ; récupération du string du nom du symbole
  mov r11d, [r10 + rcx*4] ; offset du string
  push rdx
  push rcx
  mov rcx, r8
  add rdx, r11 ; adresse du string
  call streq ; comparaison avec le symbole cible
  pop rcx
  pop rdx
  test eax, eax
  jnz .loop_through_symbols

  mov r12d, [r9 + 0x24] ; offset AddressOfNameOrdinals
  add r12, rdx ; adresse du tableau AddressOfNameOrdinals
  movzx r11, word [r12 + rcx*2]

  mov r12d, [r9 + 0x1c] ; offset AddressOfFunctions
  add r12, rdx ; AddressOfFunctions
  mov eax, [r12 + r11*4] ; offset de la fonction
  add rax, rdx ; adresse de la fonction
  ret

.fonction_introuvable:
  xor rax, rax
  ret


str_caps_kernel32: db 'KERNEL32.DLL', 0
str_GetProcAddress: db 'GetProcAddress', 0
str_GetModuleHandleA: db 'GetModuleHandleA', 0
str_ExitThread: db 'ExitThread', 0
str_LoadLibraryA: db 'LoadLibraryA', 0
str_MessageBoxA: db 'MessageBoxA', 0
str_kernel32: db 'kernel32', 0
str_user32: db 'user32', 0
str_title: db 'this is a title', 0
str_text: db 'this is a message', 0
addr_kernel32base: dq 0x0
addr_ExportDirectory: dq 0x0
addr_GetProcAddressA: dq 0x0
addr_GetModuleHandleA: dq 0x0
