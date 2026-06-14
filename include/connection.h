
#ifndef CONNECTION_H
#define CONNECTION_H

#include "protocol.h"
#include <netinet/in.h>

#define SERVER_ID 0
#define SERVER_PORT 5555
#define SERVER_ADDRESS "127.0.0.1"
#define MAX_EVENTS 512
#define MAX_ROOMS 128

typedef enum
{
    CLIENT_ITEM,
    SERVER_ITEM,
    STDIN_ITEM
} Item;

typedef struct EpollItem
{
    Item item;
    int  fd;
} EpollItem;

typedef struct Connection
{
    char   in_buf[BUF_SIZE];
    size_t in_len;

    char   out_buf[BUF_SIZE];
    size_t out_len;
    size_t out_sent;

} Connection;

typedef enum
{
    STATE_WAIT_NAME,
    STATE_WAIT_AUTH_CHALLENGE,
    STATE_WAIT_AUTH_RESPONSE,

    STATE_WAIT_REGISTER_CHALLENGE,
    STATE_WAIT_REGISTER_COMMIT,

    STATE_WAIT_KEY_BUNDLE,
    STATE_WAIT_REGISTER_OK,
    STATE_WAIT_ROOM_KEY,
    STATE_READY
} ClientState;

typedef struct Client
{
    EpollItem ei;
    uint32_t  id;
    char      name[MAX_NAME_LEN + 1];

    uint32_t           room_id;
    Connection         conn;
    ClientState        state;
    struct sockaddr_in sa;

    uint8_t* raw_kb;
    uint16_t raw_kb_len;
    int      has_kb;

    int     has_name;
    uint8_t challenge[32];
    int     auth_pending;
    int     authenticated;

    int close_after_flush;
} Client;

typedef struct Server
{
    EpollItem          ei;
    struct sockaddr_in sa;
} Server;

#endif