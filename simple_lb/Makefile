TARGET = simple_lb
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET:=.o}
USER_C = ${TARGET:=.c}

all: $(BPF_OBJ)
.PHONY: all 

%.o: %.c
	clang \
		-target bpf \
	-D __TARGET_ARCH_$(ARCH) \
		-Wall \
		-I/usr/include/x86_64-linux-gnu \
		-O2 -g -o $@ -c $<
	# llvm-strip -g $@