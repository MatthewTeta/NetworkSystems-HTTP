# Path: NetworkSystems-HTTP/Makefile
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
LDFLAGS = -lpthread
SRC_DIR = src
BUILD_DIR = build
DEFINE = -DDEBUG

all: clean build_dir server

build_dir:
	mkdir -p $(BUILD_DIR)

# %.o: %.c
# 	$(CC) $(CFLAGS) $(DEFINE) -c -o $@ $<

server: $(SRC_DIR)/server.c
	$(CC) $(CFLAGS) $(DEFINE) -o $(BUILD_DIR)/$@ $< $(LDFLAGS)

.PHONY: clean

clean:
	rm -rf $(BUILD_DIR) && rm -f $(SRC_DIR)/*.o
