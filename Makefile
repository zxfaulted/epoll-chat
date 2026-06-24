CC := gcc

OPENSSL_PREFIX := $(CURDIR)/.deps/openssl
OPENSSL_LIBDIR := $(shell if [ -d "$(OPENSSL_PREFIX)/lib64" ]; then echo "$(OPENSSL_PREFIX)/lib64"; else echo "$(OPENSSL_PREFIX)/lib"; fi)

OBJ_DIR := obj
BIN_DIR := bin
SRC_DIR := src

SRC := $(shell find $(SRC_DIR) -name '*.c')
OBJ := $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror \
          -Iinclude \
          -I$(OPENSSL_PREFIX)/include \
          -D_POSIX_C_SOURCE=200809L 

#CFLAGS += -g -O0

DEPFLAGS := -MMD -MP
DEP := $(OBJ:.o=.d)

LDFLAGS := -L$(OPENSSL_LIBDIR) -Wl,-rpath,'$$ORIGIN/lib'
LDLIBS := -lssl -lcrypto

CLIENT_SRC := $(SRC_DIR)/main/client.c
SERVER_SRC := $(SRC_DIR)/main/server.c

COMMON_SRC := $(filter-out $(CLIENT_SRC) $(SERVER_SRC), $(SRC))

COMMON_OBJS := \
	$(COMMON_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)


CLIENT_OBJ := $(CLIENT_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
SERVER_OBJ := $(SERVER_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

CLIENT_OBJS := $(CLIENT_OBJ) $(COMMON_OBJS)
SERVER_OBJS := $(SERVER_OBJ) $(COMMON_OBJS)

CLIENT := $(BIN_DIR)/client
SERVER := $(BIN_DIR)/server

.PHONY: all deps clean run

run: 
	clear
	$(MAKE) stop
	$(MAKE) $(BIN_DIR)/client $(BIN_DIR)/server
	xterm -xrm 'XTerm*selectToClipboard: true' -geometry 70x20+910+10 -hold -e "./$(BIN_DIR)/server" &
	sleep 1
	xterm -xrm 'XTerm*selectToClipboard: true' -geometry 70x20+10+10 -hold -e "./$(BIN_DIR)/client Alice" &
	sleep 1
	xterm -xrm 'XTerm*selectToClipboard: true' -geometry 70x20+460+10 -hold -e "./$(BIN_DIR)/client Bob" &

all: $(CLIENT) $(SERVER)


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
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(CLIENT): $(CLIENT_OBJS) | $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(SERVER): $(SERVER_OBJS) | $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS) $(LDLIBS)

-include $(DEP)

clean:
	rm -rf $(OBJ_DIR)/*.o $(BIN_DIR)/client $(BIN_DIR)/server $(OBJ_DIR)