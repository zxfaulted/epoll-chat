#ifndef ROOM_CRYPTO_H
#define ROOM_CRYPTO_H

#include "e2e_protocol.h"
#include "protocol.h"
#include "room_password.h"
#include "types.h"
#include <stdint.h>

int kuznechik_encrypt_room_key(uint8_t* nonce, uint8_t* enc_key, uint8_t* room_key,
                               int room_key_len, uint8_t* mac_key, uint8_t* aad, uint16_t aad_len,
                               uint8_t** out, uint16_t* out_len, uint8_t** tag_out,
                               uint16_t* tag_out_len);
int kuznechik_decrypt_room_key(uint8_t* nonce, uint8_t* enc_key, uint8_t* encrypted_room_key,
                               int encrypted_room_key_len, uint8_t* mac_key, uint8_t* aad,
                               uint16_t aad_len, uint8_t** out, uint16_t* out_len, uint8_t* tag_in,
                               uint16_t tag_in_len);
int save_peer_wrap_session(PeerWrapSession* peers, size_t count, uint32_t peer_id,
                           uint8_t* fingerprint, uint16_t fingerprint_len, uint8_t* wrapping_key);
int encrypt_room_key_with_password(uint32_t room_id, uint8_t* password, uint16_t password_len,
                                   uint8_t plaintext_room_key[ROOM_KEY_LEN], RoomPasswordInfo* rpi);
int generate_new_rpi(RoomPasswordInfo* rpi);
int try_decrypt_room_key(uint32_t room_id, uint8_t* password, uint16_t password_len,
                         RoomPasswordInfo* rpi, uint8_t out_room_key[ROOM_KEY_LEN]);
int try_decrypt_room_key_ex(uint32_t room_id, uint8_t* password, uint16_t password_len,
                            RoomPasswordInfo* rpi, uint8_t out_room_key[ROOM_KEY_LEN],
                            uint8_t out_enc_key[PASSWORD_KEY_LEN],
                            uint8_t out_mac_key[ROOM_PASS_KEY_LEN]);
int generate_room_key(uint8_t room_key[ROOM_KEY_LEN]);
int encrypt_room_key_with_password_keys(uint32_t room_id, uint8_t enc_key[PASSWORD_KEY_LEN],
                                        uint8_t           mac_key[PASSWORD_KEY_LEN],
                                        uint8_t           plaintext_room_key[ROOM_KEY_LEN],
                                        RoomPasswordInfo* rpi);

#endif