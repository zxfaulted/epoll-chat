#ifndef CLIENT_SEND_H
#define CLIENT_SEND_H

#include "connection.h"
#include "e2e_protocol.h"
#include "room_password.h"

int client_send_pkt_room_create(int epfd, Client* c, uint32_t room_id);
int client_send_pkt_room_create_password(int epfd, Client* c, uint32_t room_id,
                                         char    password[MAX_PASSWORD_LEN],
                                         uint8_t plaintext_room_key[ROOM_KEY_LEN]);
int client_send_pkt_room_join_begin(int epfd, Client* c, uint32_t room_id);
int client_send_pkt_room_unlock(int epfd, Client* c, uint32_t room_id);
int client_send_password_room_rekey(int epfd, Client* c, RoomPasswordInfo* rpi);

#endif // CLIENT_SEND_H