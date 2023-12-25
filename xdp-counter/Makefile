TARGET = xdp_counter
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET:=.bpf.o}
USER_C = ${TARGET:=.c}
USER_SKEL = ${TARGET:=.bpf.skel.h}

all: $(BPF_OBJ) $(TARGET)
.PHONY: all 

$(TARGET): $(USER_C) $(USER_SKEL) 
	gcc -Wall -o $(TARGET) $(USER_C) -L/vagrant/libbpf/src/root/usr/lib64 -l:libbpf.a -lelf -lz

%.bpf.o: %.bpf.c
	clang \
		-target bpf \
	-D __TARGET_ARCH_$(ARCH) \
		-Wall \
		-I/usr/include/x86_64-linux-gnu \
		-O2 -g -o $@ -c $<
	llvm-strip -g $@

%.bpf.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@

clean:
	- rm $(BPF_OBJ)
	- rm $(TARGET)