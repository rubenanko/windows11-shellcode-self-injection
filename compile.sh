# nettoyage du dossier tmp
if [ -d "tmp" ]; then
  rm -Rf tmp
fi
mkdir tmp

# assemblage du shellcode
nasm -f bin shellcode.s -o tmp/1-shellcode.bin

ret=$?
if [ $ret -ne 0 ]; then
  echo "erreur lors de l'assemblage du shellcode"
  exit 1
fi

# récupération du bytecode du shellcode, on parse la sortie de hexdump
bytecode=($(hexdump -X tmp/1-shellcode.bin | awk '{
  for (i=1;i<=NF;i++)
    if ($i ~ /^[0-9a-fA-F]{2}$/) printf "%s ", $i;
} END { printf "\n" }'))

# formattage du bytecode pour créer le c-array
c_array_size="${#bytecode[@]}"
c_array_content="" # va contenir "0xb0, 0x01, 0x40, ... , 0x05" 

for byte in "${bytecode[@]}"
do
    c_array_content="$c_array_content,0x$byte"
done

c_array_content="${c_array_content:1}"

# écriture du c-array
echo "int bytecode_size = $c_array_size;unsigned char bytecode[$c_array_size] = {$c_array_content};" > tmp/2-shellcode.bin.c-array

# génère un fichier C à partir du template et du c-array
c_array_code=$(cat tmp/2-shellcode.bin.c-array) # lecture du c-array
sed "s@SET_SHELLCODE_ARRAY@$c_array_code@g" main.tpl.c > tmp/3-main.c

ret=$?
if [ $ret -ne 0 ]; then
  echo "erreur lors de la création du c-array"
  exit 1
fi

# sed "s;SET_SIZE;$c_array_size;g" main.tpl.c | sed "s;SET_BYTECODE;$c_array_content;g" > tmp/3-main.c
# gcc main.c -o main -zexecstack
x86_64-w64-mingw32-gcc tmp/3-main.c -o tmp/4-pefile.exe \
  -fno-stack-protector \
  -Wl,--disable-nxcompat \
  -Wl,--disable-dynamicbase \
  -nostdlib -nodefaultlibs \
  -lkernel32 -mwindows

ret=$?
if [ $ret -ne 0 ]; then
  echo "erreur lors de la création du c-array"
  exit 1
else
  cp tmp/4-pefile.exe ./pefile.exe
  exit 0
fi
