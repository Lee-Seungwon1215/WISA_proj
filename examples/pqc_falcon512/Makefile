CC ?= gcc
CFLAGS ?= -std=c99 -O0 -g -fno-inline -fno-omit-frame-pointer
CPPFLAGS := -Iclean -I../pqc_mlkem768/common

COMMON_SRCS := \
	clean/codec.c \
	clean/common.c \
	clean/fft.c \
	clean/fpr.c \
	clean/keygen.c \
	clean/pqclean.c \
	clean/rng.c \
	clean/sign.c \
	clean/vrfy.c \
	../pqc_mlkem768/common/fips202.c \
	../pqc_mlkem768/common/randombytes.c

.PHONY: all clean

all: build/harness_sign_core_dyn build/harness_sign_core_tree

build:
	mkdir -p build

build/harness_sign_core_dyn: harness/sign_core_dyn.c $(COMMON_SRCS) | build
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@

build/harness_sign_core_tree: harness/sign_core_tree.c $(COMMON_SRCS) | build
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@

clean:
	rm -rf build
