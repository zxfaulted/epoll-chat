CC := gcc

OPENSSL_PREFIX := $(CURDIR)/.deps/openssl
OPENSSL_LIBDIR := $(shell if [ -d "$(OPENSSL_PREFIX)/lib64" ]; then echo "$(OPENSSL_PREFIX)/lib64"; else echo "$(OPENSSL_PREFIX)/lib"; fi)

CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror \
          -Iinclude \
          -I$(OPENSSL_PREFIX)/include \
          -D_POSIX_C_SOURCE=200809L

LDFLAGS := -L$(OPENSSL_LIBDIR) -Wl,-rpath,'$$ORIGIN/lib'
LDLIBS := -lssl -lcrypto

OBJ_DIR := obj
BIN_DIR := bin
SRC_DIR := src

COMMON_OBJS := \
	$(OBJ_DIR)/crypto.o \
	$(OBJ_DIR)/net.o \
		$(OBJ_DIR)/ksi.o

CLIENT_OBJS := \
	$(OBJ_DIR)/client.o \
	$(COMMON_OBJS) 

SERVER_OBJS := \
	$(OBJ_DIR)/server.o \
	$(COMMON_OBJS) 

.PHONY: all deps clean run

run: 
	$(MAKE) stop
	$(MAKE) clean
	$(MAKE) $(BIN_DIR)/client $(BIN_DIR)/server
	xterm -xrm 'XTerm*selectToClipboard: true' -geometry 70x20+910+10 -hold -e "./$(BIN_DIR)/server" &
	sleep 1
	xterm -xrm 'XTerm*selectToClipboard: true' -geometry 70x20+10+10 -hold -e "./$(BIN_DIR)/client Alice" &
	sleep 1
	xterm -xrm 'XTerm*selectToClipboard: true' -geometry 70x20+460+10 -hold -e "./$(BIN_DIR)/client Bob" &

all: $(BIN_DIR)/client $(BIN_DIR)/server


stop:
	-@pkill -f "./$(BIN_DIR)/server" 2>/dev/null || true
	-@pkill -f "./$(BIN_DIR)/client" 2>/dev/null || true

deps:
	./build_deps.sh

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/client: $(CLIENT_OBJS) | $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BIN_DIR)/server: $(SERVER_OBJS) | $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	rm -rf $(OBJ_DIR)/*.o $(BIN_DIR)/client $(BIN_DIR)/server