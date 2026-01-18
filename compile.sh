# nettoyage du dossier tmp
if [ -d "tmp" ]; then
  rm -Rf tmp
fi

mkdir tmp

# assemblage du shellcode
nasm -f bin shellcode.s -o tmp/shellcode.bin
# ld -o shellcode.exe shellcode.o

# récupération du bytecode de la fonction "_start"
bytecode=($(hexdump -X tmp/shellcode.bin | awk '{
  for (i=1;i<=NF;i++)
    if ($i ~ /^[0-9a-fA-F]{2}$/) printf "%s ", $i;
} END { printf "\n" }'))

# récupération ddu bytecode
c_array_size="${#bytecode[@]}"
c_array_content="" # va contenir "0xb0, 0x01, 0x40, ... , 0x05" 

for byte in "${bytecode[@]}"
do
    c_array_content="$c_array_content,0x$byte"
done

c_array_content="${c_array_content:1}"

# génère un fichier C à partir du template
sed "s;SET_SIZE;$c_array_size;g" main.tpl.c | sed "s;SET_BYTECODE;$c_array_content;g" > tmp/main.c
# gcc main.c -o main -zexecstack
x86_64-w64-mingw32-gcc tmp/main.c -o tmp/pefile.exe \
  -fno-stack-protector \
  -Wl,--disable-nxcompat \
  -Wl,--disable-dynamicbase