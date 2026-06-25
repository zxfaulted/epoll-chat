#ifndef SERVER_BROADCAST_H
#define SERVER_BROADCAST_H

#include "protocol/protocol.h"
#include "server/server_rooms.h"
#include "transport/connection.h"

#include <stdint.h>

void broadcast_message(int epfd, Client* c, Header* h, Client* clients[], int* clients_count,
                       const uint8_t msg[], uint32_t len, ServerRoom* server_rooms,
                       uint32_t rooms_count, uint32_t* message_id);
void broadcast_user_event(int epfd, Client* skip, uint32_t room_id, Client* clients[],
                          int* clients_count, PacketType type, ServerRoom* server_rooms,
                          uint32_t rooms_count, uint32_t* message_id);
int  send_server_ready_users(Client* c, uint32_t room_id, Client* clients[], int clients_count,
                             uint32_t* message_id);
int  send_server_ready_key_bundles(int epfd, Client* c, Client* clients[], int* clients_count,
                                   uint32_t* message_id);
int  send_server_new_key_bundle(int epfd, Client* c, Client* clients[], int clients_count,
                                uint32_t* message_id);

#endif // SERVER_BROADCAST_H