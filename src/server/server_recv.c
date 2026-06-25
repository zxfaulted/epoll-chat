#include "server/server_recv.h"

#include "protocol/pkt_build.h"
#include "protocol/wire.h"
#include "server/server_clients.h"
#include "server/server_send.h"
#include "transport/epoll_io.h"
#include "transport/packet_io.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int server_recv_pkt_room_join_begin(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id)
{
    if (!msg || !out_room_id)
    {
        return -1;
    }
    if (msg_len != ROOM_ID_LEN)
    {
        return -1;
    }
    uint32_t room_id = get_u32_be(msg);
    if (room_id < 1 || room_id > MAX_ROOMS)
    {
        return -1;
    }
    *out_room_id = room_id;
    return 0;
}

// [4 room_id]
// [8 epoch]
// [32 verifier]
int server_recv_pkt_room_unlock(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id,
                                uint64_t* out_epoch,
                                uint8_t   out_verifier[ROOM_PASSWORD_VERIFIER_LEN])
{
    int ret = -1;
    if (!msg || !out_room_id || !out_epoch || !out_verifier)
    {
        return -1;
    }
    uint8_t* p   = msg;
    uint8_t* end = msg + msg_len;

    NEED(p, end, ROOM_ID_LEN);
    uint32_t room_id = get_u32_be(p);
    *out_room_id     = room_id;
    p += ROOM_ID_LEN;

    NEED(p, end, EPOCH_LEN);
    uint64_t epoch = get_u64_be(p);
    *out_epoch     = epoch;
    p += EPOCH_LEN;

    NEED(p, end, ROOM_PASSWORD_VERIFIER_LEN);
    memcpy(out_verifier, p, ROOM_PASSWORD_VERIFIER_LEN);
    p += ROOM_PASSWORD_VERIFIER_LEN;

    if (p != end)
    {
        return -1;
    }
    ret = 0;
cleanup:
    return ret;
}

void reject_packet(int epfd, Client* c, int cur_fd, Client* clients[], int* clients_count,
                   const char* reason, ServerRoom* server_rooms, uint32_t rooms_count,
                   uint32_t* message_id)
{
    fprintf(stderr, "[REJECT] fd=%d reason=%s\n", cur_fd, reason);
    disconnect_client(epfd, c, clients, clients_count, server_rooms, rooms_count, message_id);
}