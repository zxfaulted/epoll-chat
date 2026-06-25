#ifndef ROOM_H
#define ROOM_H

#include "auth/user_table.h"
#include "common/types.h"
#include "e2e/e2e_protocol.h"
#include "transport/connection.h"

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

    int      has_key;
    uint64_t epoch;
    uint8_t  room_key[ROOM_KEY_LEN];

    int has_password;

    int     has_password_wrap_keys;
    uint8_t enc_key[PASSWORD_KEY_LEN];
    uint8_t mac_key[PASSWORD_KEY_LEN];
    uint8_t salt[ROOM_SALT_LEN];

    uint64_t send_seq;

    RoomPeerRecvState recv[MAX_CLIENTS];

    int used;
} RoomSession;

RoomSession* find_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id);
int          create_room_key(RoomSession* rooms, size_t count, uint32_t room_id);

int save_password_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id,
                               uint8_t enc_key[PASSWORD_KEY_LEN], uint8_t mac_key[PASSWORD_KEY_LEN],
                               uint8_t salt[ROOM_SALT_LEN], uint64_t epoch,
                               uint8_t room_key[ROOM_KEY_LEN]);
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
int handle_room_key(Client* c, PeerWrapSession* peers, RoomSession* rooms, Header* h, uint8_t* msg,
                    uint16_t msg_len);
int check_recv_seq(RoomSession* room, uint32_t peer_id, uint64_t recv_seq);
int rekey_current_room_auto(int epfd, Client* c, PeerWrapSession* peers, uint16_t peers_count,
                            RoomSession* rooms, uint16_t rooms_count, UserEntry* ue,
                            uint32_t room_id);
RoomSession* find_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id);
int          validate_room_join(RoomSession* rooms, uint32_t room_id);
void         clear_room_session(RoomSession* room);
int rekey_current_password_room(int epfd, Client* c, PeerWrapSession* peers, uint16_t peers_count,
                                RoomSession* rooms, uint16_t rooms_count, UserEntry* ue,
                                uint32_t room_id);

#endif // ROOM_H