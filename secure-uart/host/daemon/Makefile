# SPDX-License-Identifier: MIT
# Copyright (C) 2024, Secure UART Project

# Compiler and flags
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
LDFLAGS ?=
LIBS = -lteec -lutil -lpthread

# Directories
SRC_DIR = src
BUILD_DIR ?= build
BIN_DIR ?= bin

# Target
TARGET = secure-uart-daemon

CPPFLAGS += -I$(SRC_DIR) -I../../include

# Source files
SRCS = $(SRC_DIR)/main.c \
       $(SRC_DIR)/packet.c \
       $(SRC_DIR)/tee_client.c \
       $(SRC_DIR)/uart_handler.c \
       $(SRC_DIR)/pty_manager.c

# Object files
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

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

# Clean
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# Install (for Yocto)
install: all
	install -d $(DESTDIR)/usr/bin
	install -m 0755 $(BIN_DIR)/$(TARGET) $(DESTDIR)/usr/bin/

.PHONY: all clean install
