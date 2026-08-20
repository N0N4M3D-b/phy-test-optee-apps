# SPDX-License-Identifier: MIT
# Copyright (C) 2024, Secure UART Project

CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
LDFLAGS ?=
LIBS = -lteec

SRC_DIR = src
INC_DIR = include
BUILD_DIR ?= build
BIN_DIR ?= bin
TARGET = ta-test-app

CPPFLAGS += -I$(INC_DIR) -I../include

SRCS = $(SRC_DIR)/main.c \
       $(SRC_DIR)/test_basic.c
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

all: $(BIN_DIR)/$(TARGET)

$(BUILD_DIR) $(BIN_DIR):
	mkdir -p $@

$(BIN_DIR)/$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

install: all
	install -d $(DESTDIR)/usr/bin
	install -m 0755 $(BIN_DIR)/$(TARGET) $(DESTDIR)/usr/bin/

.PHONY: all clean install
