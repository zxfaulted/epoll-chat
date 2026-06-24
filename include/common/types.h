#ifndef TYPES_H
#define TYPES_H

#include "protocol/protocol.h"
#include <netinet/in.h>
#include <stdint.h>

typedef struct PeerWrapSession
{
    uint32_t peer_id;

    uint8_t  fingerprint[64];
    uint16_t fingerprint_len;

    uint8_t wrapping_key[32];

    int used;
} PeerWrapSession;

typedef enum
{
    ROOM_KEY_ERROR    = -1,
    ROOM_KEY_IGNORED  = 0,
    ROOM_KEY_ACCEPTED = 1
} RoomKeyResult;

#endif