CFLAGS ?= -march=native -O3 -fomit-frame-pointer -pipe
CFLAGS += -std=c11 -Wall

git-daemon-dummy: git-daemon-dummy.c seccomp-bpf.h
clean:
	rm -f git-daemon-dummy

.PHONY: clean
