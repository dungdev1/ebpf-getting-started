# Compile ebpf program
clang -target bpf -g hello.bpf.c -o hello.bpf.o -O2
## dump ebpf byte code
llvm-objdump-10 -S hello.bpf.o

# Program
# 1. List all ebpf programs
bpftool prog list
# 2. Load ebpf program into kernel
bpftool prog load hello.bpf.o /sys/fs/bpf/hello
# 3. Show programs
bpftool prog show
bpftool prog show id 184 --pretty
# 4. Dump ebpf program
# bytecode
bpftool prog dump xlated id 184
# machine code
bpftool prog dump jited id 184
# 5. enable jit compiler (enabled by default)
echo 1 > /proc/sys/net/core/bpf_jit_enable
# 6. unloading hello program
rm /sys/fs/bpf/hello

# Attach program to an event
bpftool net list
# 1. Attach program with id 184 to xdp event, so this program will run whenever a packet reach the enp0s3 network interface
bpftool net attach xdp id 184 dev enp0s3
# 2. Detach program from event
bpftool net detach xdp dev enp0s3

# Map
# 1. List maps
bpftool map list
bpftool map list --pretty
# 2. Dump map
bpftool map dump id 29