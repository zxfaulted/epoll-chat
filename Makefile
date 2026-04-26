SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := bin
KEYS_DIR := keys


SERVER := $(BIN_DIR)/server
CLIENT := $(BIN_DIR)/client
SERVER_OBJ := $(OBJ_DIR)/server.o $(OBJ_DIR)/net.o # $(OBJ_DIR)/crypto.o
CLIENT_OBJ := $(OBJ_DIR)/client.o $(OBJ_DIR)/net.o # $(OBJ_DIR)/crypto.o
SRC := $(SRC_DIR)/server.c $(SRC_DIR)/client.c
CC := gcc

#CFLAGS := -Wall -Wextra -pedantic -Iinclude -g -O0 -fsanitize=address -fno-omit-frame-pointer
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror -Iinclude

.PHONY: run run-server run-client stop clean

run: stop clean all 
	xterm -xrm 'XTerm*selectToClipboard: true' -geometry 70x20+10+10 -hold -e "./$(SERVER)" &
	sleep 0.1
	xterm -xrm 'XTerm*selectToClipboard: true' -geometry 70x20+460+10 -hold -e "./$(CLIENT)" &
	sleep 0.1
	xterm -xrm 'XTerm*selectToClipboard: true' -geometry 70x20+910+10 -hold -e "./$(CLIENT)" &

run-server: $(SERVER) 
	./$(SERVER)

run-client: $(CLIENT)
	./$(CLIENT)

all: $(SERVER) $(CLIENT)

$(SERVER): $(SERVER_OBJ)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@

$(CLIENT): $(CLIENT_OBJ)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(OBJ_DIR)
	mkdir -p $(KEYS_DIR)
	chmod 700 $(KEYS_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

stop:
	-pkill -f ./$(SERVER)
	-pkill -f ./$(CLIENT)

clean: stop
	rm -rf $(OBJ_DIR) $(BIN_DIR)