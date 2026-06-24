#include "e2e/room_key_wrap.h"

#include "crypto/crypto.h"
#include "crypto/crypto_core.h"
#include "e2e/room_crypto.h"
#include "protocol/wire.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

int e2e_wrap_room_key(uint32_t client_id, uint32_t peer_id, uint32_t room_id, uint64_t epoch,
                      uint8_t* wrapping_key, uint8_t* room_key, uint8_t* out_cipher,
                      uint8_t* out_tag, uint8_t* out_nonce)
{
    int      ret        = -1;
    uint8_t* cipher     = NULL;
    uint16_t cipher_len = 0;
    uint8_t* tag        = NULL;
    uint16_t tag_len    = 0;

    uint8_t mac_key[32]           = {0};
    uint8_t enc_key[32]           = {0};
    uint8_t nonce[ROOM_NONCE_LEN] = {0};

    uint8_t aad[AAD_LEN];
    if (build_aad(aad, client_id, peer_id, room_id, epoch) < 0)
    {
        fprintf(stderr, "build_aad failed\n");
        goto cleanup;
    }
    const unsigned char salt_enc[] = "room-key-wrap enc";
    if (get_kdf(wrapping_key, WRAPPING_KEY_LEN, salt_enc, (uint16_t)(sizeof(salt_enc) - 1), aad,
                AAD_LEN, enc_key, 32) < 0)
    {
        fprintf(stderr, "get_kdf failed\n");
        goto cleanup;
    }
    const unsigned char salt_mac[] = "room-key-wrap mac";
    if (get_kdf(wrapping_key, WRAPPING_KEY_LEN, salt_mac, (uint16_t)(sizeof(salt_mac) - 1), aad,
                AAD_LEN, mac_key, 32) < 0)
    {
        fprintf(stderr, "get_kdf failed\n");
        goto cleanup;
    }

    if (RAND_bytes(nonce, PKT_ENC_ROOM_KEY_NONCE_LEN) != 1)
    {
        ossl_print_error("RAND_bytes");
        goto cleanup;
    }

    if (kuznechik_encrypt_room_key(nonce, enc_key, room_key, ROOM_KEY_LEN, mac_key, aad,
                                   sizeof(aad), &cipher, &cipher_len, &tag, &tag_len) < 0)
    {
        fprintf(stderr, "kuznechik_encrypt_room_key failed\n");
        goto cleanup;
    }
    if (cipher_len != PKT_ENC_ROOM_KEY_CIPHERTEXT_LEN)
    {
        fprintf(stderr, "cipher_len mismatch\n");
        goto cleanup;
    }
    if (tag_len != PKT_ENC_ROOM_KEY_TAG_LEN)
    {
        fprintf(stderr, "cipher_len mismatch\n");
        goto cleanup;
    }
    memcpy(out_cipher, cipher, cipher_len);
    memcpy(out_tag, tag, tag_len);
    memcpy(out_nonce, nonce, ROOM_NONCE_LEN);
    ret = 0;
cleanup:
    OPENSSL_cleanse(mac_key, 32);
    OPENSSL_cleanse(enc_key, 32);
    OPENSSL_free(cipher);
    OPENSSL_free(tag);

    return ret;
}
