#ifndef SERVER_CLIENTS_H
#define SERVER_CLIENTS_H

#include "protocol/protocol.h"
#include "transport/connection.h"

#include <stddef.h>
#include <stdint.h>

int add_new_client(int epfd, int server_fd, Client* clients[], int* clients_count, uint32_t* id);
Client*  find_client(Client* clients[], int clients_count, uint32_t client_id);
int      is_name_taken(Client* clients[], int clients_count, const char* name, size_t name_len);
int      disconnect_client(int epfd, Client* c, Client* clients[], int* clients_count,
                           uint32_t* message_id);
uint32_t clients_leader_id(Client** clients, int clients_count, uint32_t room_id);
int      set_client_name(Client* c, const char* msg, size_t msg_len);

#endif // SERVER_CLIENTS_H