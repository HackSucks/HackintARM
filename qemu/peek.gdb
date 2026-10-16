set pagination off
set confirm off
set architecture aarch64
target remote 127.0.0.1:1234

printf "\n=== VA 0xfffffe0007faa750 (arm_init as the CPU sees it) ===\n"
x/10i 0xfffffe0007faa750
printf "\n=== raw bytes at VA ===\n"
x/24xb 0xfffffe0007faa750
printf "\n=== raw bytes at PA 0x80faa750 ===\n"
x/24xb 0x80faa750
printf "\n=== registers ===\n"
info registers pc sp x19 x30
detach
quit
