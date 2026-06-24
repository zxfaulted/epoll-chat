#ifndef SERVER_SEND_H
#define SERVER_SEND_H

#include "e2e/room_password_packet.h"
#include "server/server_rooms.h"
#include "transport/connection.h"

int send_server_error(int epfd, Client* c, const char msg[], uint32_t* message_id);
int server_send_pkt_room_create_ok(int epfd, Client* c, uint32_t room_id, uint32_t* message_id);
int server_send_room_password_info(int epfd, Client* c, uint32_t room_id, RoomPasswordInfo* rpi,
                                   uint32_t* message_id);
int send_server_auth_ok(Client* c, uint32_t room_id, const char* name, uint32_t user_id,
                        uint32_t* message_id);
int send_server_register_ok(Client* c, uint32_t room_id, const char* name, uint32_t user_id,
                            uint32_t* message_id);
int send_server_user_event(Client* c, uint32_t room_id, PacketType type, const char* name,
                           uint32_t user_id, uint32_t* message_id);
int forward_room_key_packet(int epfd, Client* clients[], int clients_count, Client* from, Header* h,
                            uint8_t* msg, uint32_t msg_len, uint32_t* message_id);

#endif // SERVER_SEND_H