#ifndef ROOM_CRYPTO_H
#define ROOM_CRYPTO_H

#include "e2e_protocol.h"
#include "protocol.h"
#include "types.h"
#include <stdint.h>

int kuznechik_encrypt_room_key(uint8_t* nonce, uint8_t* enc_key, uint8_t* room_key,
                               int room_key_len, uint8_t* mac_key, uint8_t aad[AAD_LEN],
                               uint8_t** out, uint16_t* out_len, uint8_t** tag_out,
                               uint16_t* tag_out_len);
int kuznechik_decrypt_room_key(uint8_t* nonce, uint8_t* enc_key, uint8_t* encrypted_room_key,
                               int encrypted_room_key_len, uint8_t* mac_key, uint8_t aad[AAD_LEN],
                               uint8_t** out, uint16_t* out_len, uint8_t* tag_in,
                               uint16_t tag_in_len);
int save_peer_wrap_session(PeerWrapSession* peers, size_t count, uint32_t peer_id,
                           uint8_t* fingerprint, uint16_t fingerprint_len, uint8_t* wrapping_key);

#endif