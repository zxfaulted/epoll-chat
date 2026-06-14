#ifndef KEY_BUNDLE_H
#define KEY_BUNDLE_H

#include "connection.h"
#include "types.h"
#include "user_table.h"
#include <openssl/evp.h>
#include <stdint.h>

#define VKO_TTL_SECONDS 4800
#define MAX_PUBKEY_LEN 128

typedef struct RoomSession RoomSession;

// идентификация: ГОСТ Р 34.10-2012 512
// обмен секретом: VKO ГОСТ Р 34.10-2012 512
// хеш: Стрибог-512
// подпись: ГОСТ Р 34.10-2012 + Стрибог-512
// чат: Кузнечик-ctr-acpkm

typedef struct
{
    uint8_t  bundle_version;
    uint32_t client_id;

    // gost2012_256
    // gost2012_512
    uint8_t  identity_alg;
    uint16_t identity_pub_len;
    uint8_t* identity_pub;

    // выработка ключа общего (секрета)
    // gost2012_256
    // gost2012_512
    uint8_t  vko_alg;
    uint16_t vko_pub_len;
    uint8_t* vko_pub;
    uint64_t vko_expires_at;

    // md_gost12_512
    // подпись только публичного ключа
    // для его идентификации
    uint8_t  fingerprint_alg;
    uint16_t fingerprint_len;
    uint8_t* fingerprint;

    // 1 = gost3410_2012_256_with_gost3411_2012_256
    // 2 = gost3410_2012_512_with_gost3411_2012_512
    // gost2012_256
    // подпись всего bundle кроме самой signature
    uint8_t  signature_alg;
    uint16_t signature_len;
    uint8_t* signature;

} KeyBundle;

int kb_clear(KeyBundle* kb);
int kb_free(KeyBundle* kb);
int init_key_bundle(KeyBundle* kb, uint32_t client_id, EVP_PKEY* private_key,
                    const char* temp_user);
int send_kb(Client* c, uint8_t* kb, uint16_t kb_len, uint32_t owner_id, uint32_t room_id,
            uint32_t* message_id);
int get_sign_kb(KeyBundle* kb, EVP_PKEY* private_key, unsigned char** out, size_t* out_len);

int verify_sign(KeyBundle* kb, EVP_PKEY* public_key);
int verify_key_bundle(const uint8_t* data, uint16_t data_len);

int serialize_key_bundle_to_sign(KeyBundle* kb, uint8_t** out, uint16_t* out_len);
int serialize_key_bundle_full(KeyBundle* kb, uint8_t** out, uint16_t* out_len);

KeyBundle* deserialize_key_bundle_full(const uint8_t* data, uint16_t data_len);
int        handle_kb(int epfd, uint8_t* data, uint16_t data_len, KeyBundle* my_kb,
                     EVP_PKEY* my_vko_private, PeerWrapSession* peers, size_t peers_count,
                     RoomSession* rooms, size_t rooms_count, UserEntry* ue, Client* c);
int        validate_key_bundle_algorithms(KeyBundle* kb);
int        send_server_ready_key_bundles(int epfd, Client* c, Client* clients[], int* clients_count,
                                         uint32_t* message_id);
int        send_server_new_key_bundle(int epfd, Client* c, Client* clients[], int clients_count,
                                      uint32_t* message_id);

#endif