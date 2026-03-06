# Basic standalone Makefile for fw_env_scan
#
# Usage:
#   make
#   make static
#   make CC=arm-linux-gnueabi-gcc static

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
LDFLAGS ?=

TARGET  ?= fw_env_scan
SRC     ?= fw_env_scan.c

.PHONY: all static clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

static: LDFLAGS += -static
static: all

clean:
	rm -f $(TARGET)