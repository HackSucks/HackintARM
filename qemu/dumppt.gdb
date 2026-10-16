set pagination off
set confirm off
set architecture aarch64
target remote 127.0.0.1:1234
dump binary memory /tmp/opencode/pt.bin 0x80230000 0x80240000
printf "dumped\n"
detach
quit
