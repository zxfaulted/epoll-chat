#ifndef STATE_RULES_H
#define STATE_RULES_H

#include "auth.h"
#include "protocol.h"

int server_packet_allow(Client* c, PacketType type, AuthState auth);

#endif // STATE_RULES_H