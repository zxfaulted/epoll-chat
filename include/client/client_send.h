#ifndef CLIENT_SEND_H
#define CLIENT_SEND_H

#include "e2e/client_room_session.h"
#include "e2e/room_password_packet.h"
#include "transport/connection.h"

#include <openssl/evp.h>
#include <stdint.h>

int client_send_pkt_room_create(int epfd, Client* c, uint32_t room_id);
int client_send_pkt_room_create_password(int epfd, Client* c, uint32_t room_id,
                                         char    password[MAX_PASSWORD_LEN],
                                         uint8_t plaintext_room_key[ROOM_KEY_LEN]);
int client_send_pkt_room_join_begin(int epfd, Client* c, uint32_t room_id);
int client_send_pkt_room_unlock(int epfd, Client* c, uint32_t room_id, uint64_t epoch,
                                uint8_t verifier[ROOM_PASSWORD_VERIFIER_LEN]);
int client_send_password_room_rekey(int epfd, Client* c, RoomPasswordInfo* rpi);
int client_send_register_commit(int epfd, Client* c, uint8_t* identity_pub_der,
                                uint16_t identity_pub_der_len, uint8_t* sig, uint16_t siglen);
int client_send_encrypted_chat(int epfd, Client* c, RoomSession* room, uint8_t* msg,
                               uint16_t msg_len);
int client_send_challenge_response(int epfd, Client* c, uint8_t* msg, uint16_t msg_len,
                                   EVP_PKEY* private_key);
int send_room_key_to_peer(int epfd, Client* c, uint32_t peer_id, uint8_t* wrapping_key,
                          RoomSession* room);

#endif // CLIENT_SEND_H