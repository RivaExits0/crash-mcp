CC ?= gcc
CORE ?= tests/core

all:
	$(CC) -O0 -g -static -o tests/crash tests/crash.c
	ulimit -c unlimited && (cd tests && ./crash) || true

test: all
	python3 -m pytest -q

clean:
	rm -f tests/crash tests/core

.PHONY: all test clean