#ifndef ROOM_JOIN_H
#define ROOM_JOIN_H
#include "transport.h"

#define MIN_PASSWORD_LEN 4
#define MAX_PASSWORD_LEN 128

int client_send_pkt_room_join_begin(int epfd, Client* c, uint32_t room_id,
                                    char password[MAX_PASSWORD_LEN]);

#endif // ROOM_JOIN_H
