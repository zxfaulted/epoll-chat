#ifndef SERVER_SEND_H
#define SERVER_SEND_H

#include "connection.h"
#include "room_password.h"
#include "server_room.h"

int send_server_error(int epfd, Client* c, const char msg[], uint32_t* message_id);
int server_send_pkt_room_create_ok(int epfd, Client* c, uint32_t room_id, uint32_t* message_id);
int server_send_room_password_info(int epfd, Client* c, uint32_t room_id, RoomPasswordInfo* rpi,
                                   uint32_t* message_id);

#endif // SERVER_SEND_H