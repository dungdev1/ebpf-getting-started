#!/usr/bin/python3
from bcc import BPF

program = """
int hello_world(void *ctx) {
    bpf_trace_printk("Hello World  !\\n");
    return 0;
}
"""

# create bpf object with predefined ebpf program
b = BPF(text=program)

# ebpf program need to be attached to an event, so need to look up the function name of syscall
# Although the execve() name is a standard interface in Linux, but the name of function that implements it 
# in the kernel depends on the chip architecture.
syscall = b.get_syscall_fnname("execve")

# attach the program to execve event
b.attach_kprobe(event=syscall, fn_name="hello_world")

# read from the kernel debug trace pipe and print on stdout
b.trace_print()