# Path: NetworkSystems-HTTP/Makefile
CC = gcc
CFLAGS = -Wall -Wextra -O3
SRC_DIR = src
BUILD_DIR = build
# DEFINE = -DDEBUG
DEFINE =

all: clean build_dir server

build_dir:
	mkdir -p $(BUILD_DIR)

# %.o: %.c
# 	$(CC) $(CFLAGS) $(DEFINE) -c -o $@ $<

server: $(SRC_DIR)/server.c
	$(CC) $(CFLAGS) $(DEFINE) -o $(BUILD_DIR)/$@ $<

.PHONY: clean

clean:
	rm -rf $(BUILD_DIR) && rm -f $(SRC_DIR)/*.o
