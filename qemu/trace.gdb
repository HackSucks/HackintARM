set pagination off
set confirm off
set architecture aarch64
target remote 127.0.0.1:1234

# XNU entry, identity (V=P) physical address
hb *0x803e4480
continue

printf "\n=== hit _start  pc=%#lx ===\n", $pc

set $n = 0
while $n < 140
  printf "%#lx  ", $pc
  x/i $pc
  stepi
  set $n = $n + 1
  # stop early if we land on XNU's spinning low exception vector
  if $pc >= 0x803e5000 && $pc < 0x803e6000
    printf "\n*** landed on low exception vector (pc=%#lx) ***\n", $pc
    set $n = 999
  end
end

printf "\n=== stop pc=%#lx sp=%#lx\n", $pc, $sp
info registers pc x0 x1 x19 x20 x21 x22 x23 x24 x25 x30 sp
detach
quit
