# SPDX-License-Identifier: MIT
# Copyright (C) 2024, Secure UART Project

# Compiler and flags
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
LDFLAGS ?=
LIBS = -lteec

# Directories
SRC_DIR = src
BUILD_DIR ?= build
BIN_DIR ?= bin

# Target
TARGET = secure-uart-test

INFRA_TEST_DIR = ../../infra-test
CPPFLAGS += -I$(SRC_DIR) \
            -I$(INFRA_TEST_DIR)/host/include \
            -I$(INFRA_TEST_DIR)/include \
            -I../../secure-uart/include

# Source files
SRCS = $(SRC_DIR)/main.c \
       $(SRC_DIR)/test_secure_uart.c

INFRA_TEST_SRC = $(INFRA_TEST_DIR)/host/src/test_basic.c

# Object files
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
OBJS += $(BUILD_DIR)/test_basic.o

# Default target
all: $(BUILD_DIR) $(BIN_DIR) $(BIN_DIR)/$(TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Create bin directory
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Link
$(BIN_DIR)/$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Built: $@"

# Compile
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/test_basic.o: $(INFRA_TEST_SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

# Clean
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# Install (for Yocto)
install: all
	install -d $(DESTDIR)/usr/bin
	install -m 0755 $(BIN_DIR)/$(TARGET) $(DESTDIR)/usr/bin/

.PHONY: all clean install
