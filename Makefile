# Path: NetworkSystems-HTTP/Makefile
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
LDFLAGS = -lpthread
SRC_DIR = src
BUILD_DIR = build
DEFINE = -DDEBUG

all: server

server: src/server.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEFINE) -o $(BUILD_DIR)/server $(SRC_DIR)/server.c
