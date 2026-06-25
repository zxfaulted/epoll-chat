CC := gcc

OPENSSL_PREFIX := $(CURDIR)/.deps/openssl
OPENSSL_LIBDIR := $(shell if [ -d "$(OPENSSL_PREFIX)/lib64" ]; then echo "$(OPENSSL_PREFIX)/lib64"; else echo "$(OPENSSL_PREFIX)/lib"; fi)

GOSTPROV := $(shell find "$(OPENSSL_PREFIX)" -name 'gostprov.so' 2>/dev/null | head -n 1)

OBJ_DIR := obj
BIN_DIR := bin
SRC_DIR := src

RUNTIME_LIBDIR := $(BIN_DIR)/lib
RUNTIME_MODULEDIR := $(BIN_DIR)/ossl-modules


CLIENT := $(BIN_DIR)/client
SERVER := $(BIN_DIR)/server

CLIENT_SRC := $(SRC_DIR)/main/client.c
SERVER_SRC := $(SRC_DIR)/main/server.c

SRC := $(shell find $(SRC_DIR) -name '*.c')
COMMON_SRC := $(filter-out $(CLIENT_SRC) $(SERVER_SRC), $(SRC))

COMMON_OBJS := $(COMMON_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
CLIENT_OBJ := $(CLIENT_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
SERVER_OBJ := $(SERVER_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

CLIENT_OBJS := $(CLIENT_OBJ) $(COMMON_OBJS)
SERVER_OBJS := $(SERVER_OBJ) $(COMMON_OBJS)

DEP := $(CLIENT_OBJS:.o=.d) $(SERVER_OBJS:.o=.d)

CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror \
          -Iinclude \
          -I$(OPENSSL_PREFIX)/include \
          -D_POSIX_C_SOURCE=200809L

# Debug:
# CFLAGS += -g -O0

DEPFLAGS := -MMD -MP

LDFLAGS := -L$(OPENSSL_LIBDIR) -Wl,-rpath,'$$ORIGIN/lib'
LDLIBS := -lssl -lcrypto

.DEFAULT_GOAL := all

.PHONY: all clean deps stop demo client alice bob server runtime


runtime:
	@test -n "$(GOSTPROV)" || { echo "gostprov.so not found. Run: make deps"; exit 1; }
	@mkdir -p $(RUNTIME_LIBDIR) $(RUNTIME_MODULEDIR)
	cp -a $(OPENSSL_LIBDIR)/libcrypto.so* $(RUNTIME_LIBDIR)/
	cp -a $(OPENSSL_LIBDIR)/libssl.so* $(RUNTIME_LIBDIR)/ 2>/dev/null || true
	cp -a "$(GOSTPROV)" $(RUNTIME_MODULEDIR)/

all: runtime $(CLIENT) $(SERVER)

$(OBJ_DIR):
	mkdir -p $@

$(BIN_DIR):
	mkdir -p $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(CLIENT): $(CLIENT_OBJS) | $(BIN_DIR) runtime
	$(CC) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(SERVER): $(SERVER_OBJS) | $(BIN_DIR) runtime
	$(CC) $^ -o $@ $(LDFLAGS) $(LDLIBS)

deps:
	./build_deps.sh

stop:
	-@pkill -f "$(SERVER)" 2>/dev/null || true
	-@pkill -f "$(CLIENT)" 2>/dev/null || true

RUN_ENV := LD_LIBRARY_PATH="$(CURDIR)/$(RUNTIME_LIBDIR)" OPENSSL_MODULES="$(CURDIR)/$(RUNTIME_MODULEDIR)"

server: $(SERVER)
	@command -v kitty >/dev/null || { echo "kitty not found"; exit 1; }
	@command -v wmctrl >/dev/null || { echo "wmctrl not found"; exit 1; }
	kitty --title CHAT_SERVER sh -lc '$(RUN_ENV) ./$(SERVER); echo; echo "[Server exited]"; exec sh' 2>/dev/null &
	sleep 0.7
	wmctrl -r CHAT_SERVER -e 0,1410,40,400,420

client: $(CLIENT)
	@command -v kitty >/dev/null || { echo "kitty not found"; exit 1; }
	@command -v wmctrl >/dev/null || { echo "wmctrl not found"; exit 1; }
	kitty --title CHAT_CLIENT sh -lc '$(RUN_ENV) ./$(CLIENT) Client; echo; echo "[Client exited]"; exec sh' 2>/dev/null &
	sleep 0.7
	wmctrl -r CHAT_CLIENT -e 0,100,40,650,420

alice: $(CLIENT)
	@command -v kitty >/dev/null || { echo "kitty not found"; exit 1; }
	@command -v wmctrl >/dev/null || { echo "wmctrl not found"; exit 1; }
	kitty --title CHAT_ALICE sh -lc '$(RUN_ENV) ./$(CLIENT) Alice; echo; echo "[Alice exited]"; exec sh' 2>/dev/null &
	sleep 0.7
	wmctrl -r CHAT_ALICE -e 0,100,40,650,420

bob: $(CLIENT)
	@command -v kitty >/dev/null || { echo "kitty not found"; exit 1; }
	@command -v wmctrl >/dev/null || { echo "wmctrl not found"; exit 1; }
	kitty --title CHAT_BOB sh -lc '$(RUN_ENV) ./$(CLIENT) Bob; echo; echo "[Bob exited]"; exec sh' 2>/dev/null &
	sleep 0.7
	wmctrl -r CHAT_BOB -e 0,755,40,650,420

demo: all
	@command -v kitty >/dev/null || { echo "kitty not found"; exit 1; }
	@command -v wmctrl >/dev/null || { echo "wmctrl not found"; exit 1; }

	$(MAKE) stop

	kitty --title CHAT_SERVER sh -lc "./$(SERVER); echo; echo '[server exited]'; exec sh" 2>/dev/null &
	sleep 0.7
	wmctrl -r CHAT_SERVER -e 0,1410,40,400,420

	kitty --title CHAT_ALICE sh -lc "./$(CLIENT) Alice; echo; echo '[Alice exited]'; exec sh" 2>/dev/null &
	sleep 0.7
	wmctrl -r CHAT_ALICE -e 0,100,40,650,420

	kitty --title CHAT_BOB sh -lc "./$(CLIENT) Bob; echo; echo '[Bob exited]'; exec sh" 2>/dev/null &
	sleep 0.7
	wmctrl -r CHAT_BOB -e 0,755,40,650,420

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

-include $(DEP)