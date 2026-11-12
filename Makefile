PYTHON ?= python3
CC ?= gcc

.PHONY: all core test clean

all: core

core: tests/crash
	$(PYTHON) tests/make_core.py

tests/crash: tests/crash.c
	$(CC) -O0 -g -static -fno-pie -no-pie -o tests/crash tests/crash.c

test: core
	$(PYTHON) -m pytest -q

clean:
	rm -f tests/crash tests/core core core.* *.core
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
