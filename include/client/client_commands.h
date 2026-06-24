#ifndef CLIENT_COMMANDS_H
#define CLIENT_COMMANDS_H

#include "crypto/crypto.h"
#include "e2e/client_room_session.h"
#include "transport/connection.h"

int  handle_input(int epfd, Client* c, RoomSession* rooms, GeneratedKeys* gk, char* out_buf,
                  ssize_t bytes, const char* default_name, int* registration_in_progress,
                  int* generated_keys_for_registration);
void print_help(Client* c);
int  send_name_command(int epfd, Client* c, uint8_t pkt_type, const char* user_name);

#endif // CLIENT_COMMANDS_H