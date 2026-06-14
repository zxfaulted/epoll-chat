#ifndef ROOM_H
#define ROOM_H

#include "connection.h"
#include "e2e_protocol.h"
#include "types.h"
#include "user_table.h"

typedef struct RoomPeerRecvState
{
    uint32_t peer_id;
    uint64_t seq;
    int      used;

} RoomPeerRecvState;

typedef struct RoomSession
{
    uint32_t room_id;
    uint32_t owner_id;

    int     has_pass_key;
    uint8_t room_pass_key[ROOM_PASS_KEY_LEN];

    uint64_t epoch;
    uint8_t  room_key[ROOM_KEY_LEN];

    uint64_t send_seq;

    RoomPeerRecvState recv[MAX_CLIENTS];

    int used;
} RoomSession;

RoomSession* find_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id);
int          create_room_key(RoomSession* rooms, size_t count, uint32_t room_id);
int save_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id, uint64_t epoch,
                      uint8_t room_key[ROOM_KEY_LEN]);
RoomSession* get_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id);
uint64_t     get_room_epoch(RoomSession* room);
int rekey_current_room_as_leader(int epfd, Client* c, PeerWrapSession* peers, size_t peers_count,
                                 RoomSession* rooms, size_t rooms_count, UserEntry* ue);
int rekey_current_room(int epfd, Client* c, PeerWrapSession* peers, size_t peers_count,
                       RoomSession* rooms, size_t rooms_count, UserEntry* ue);
int send_room_key_to_known_peers(int epfd, Client* c, PeerWrapSession* peers, size_t peers_count,
                                 RoomSession* rooms, size_t rooms_count, UserEntry* ue);
PeerWrapSession* find_peer_wrap_session(PeerWrapSession* peers, size_t count, uint32_t peer_id);
int send_room_key_to_peer(Client* c, uint32_t peer_id, uint8_t* wrapping_key, RoomSession* room);
int forward_room_key_packet(int epfd, Client* clients[], int clients_count, Client* from, Header* h,
                            uint8_t* msg, uint32_t msg_len, uint32_t* message_id);
int handle_room_key(Client* c, PeerWrapSession* peers, RoomSession* rooms, Header* h, uint8_t* msg,
                    uint16_t msg_len);
int check_recv_seq(RoomSession* room, uint64_t peer_id, uint64_t recv_seq);
#endif // ROOM_H