#ifndef CRYPTO_H
#define CRYPTO_H

#include "net.h"
#include "protocol.h"
#include <openssl/evp.h>
#include <openssl/provider.h>

#define VKO_TTL_SECONDS 4800
#define MAX_PUBKEY_LEN 128

// AAD
// [1  packet_type]
// [4  sender_id]
// [4  to_client_id]
// [4 room_id]
// [8  epoch]
#define PACKET_TYPE_LEN 1
#define SENDER_ID_LEN 4
#define TO_CLIENT_ID_LEN 4
#define ROOM_ID_LEN 4
#define EPOCH_LEN 8
#define AAD_LEN (PACKET_TYPE_LEN + SENDER_ID_LEN + TO_CLIENT_ID_LEN + ROOM_ID_LEN + EPOCH_LEN)

// PKT_ENC_CHAT
// [1  enc_version]
// [1  suite]
// [2  reserved]
// [8  room_epoch]
// [8  seq]
// [16 nonce]
// [N  ciphertext]
// [16 tag]
#define ENC_VERSION 1
#define ENC_SUITE 1
#define ENC_RESERVED 2
#define ENC_ROOM_EPOCH 8
#define ENC_SEQ 8
#define ENC_NONCE 16
#define ENC_TAG 16
#define ENC_HEADER (ENC_VERSION + ENC_SUITE + ENC_RESERVED + ENC_ROOM_EPOCH + ENC_SEQ + ENC_NONCE)
#define ENC_OVERHEAD (ENC_HEADER + ENC_TAG)
#define ENC_PLAINTEXT_MAX_LEN (PAYLOAD_SIZE - ENC_OVERHEAD)

// [1 packet_type]
// [1 enc_version]
// [1 suite]
// [2 reserved]
// [4 sender_id]
// [4 room_id]
// [8 room_epoch]
// [8 seq]
#define AAD_FOR_ENC_CHAT_LEN                                                                       \
    (PACKET_TYPE_LEN + ENC_VERSION + ENC_SUITE + ENC_RESERVED + SENDER_ID_LEN + ROOM_ID_LEN +      \
     ENC_ROOM_EPOCH + ENC_SEQ)

#define AUTH_CHALLENGE_NONCE_LEN 32
#define AUTH_CHALLENGE_PAYLOAD_LEN (SENDER_ID_LEN + AUTH_CHALLENGE_NONCE_LEN)

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
// Encoder / Decoder
//  gost2012_512 / gost2012_512

// Ключи идентификации
typedef enum
{
    IKA_NONE = 0,
    // ГОСТ Р 34.10-2012 256 бит + Стрибог 256 бит
    //
    IKA_GOST2012_256 = 1,
    // ГОСТ Р 34.10-2012 512 бит + Стрибог 512 бит
    IKA_GOST2012_512 = 2
} IdentityKeyAlg;

typedef enum
{
    VKO_NONE = 0,
    // ГОСТ Р 34.10-2012 256 бит
    VKO_GOST2012_256 = 1,
    // ГОСТ Р 34.10-2012 512 бит
    VKO_GOST2012_512 = 2
} VKOAlg;

// Алгоритмы отпечатка (хэш)
typedef enum
{
    FA_NONE = 0,
    // Стрибог 256 бит (ГОСТ Р. 34.11-2012)
    FA_GOST2012_256 = 1,
    // Стрибог 512 бит (ГОСТ Р. 34.11-2012)
    FA_GOST2012_512 = 2
} FingerprintAlg;

typedef enum
{
    // 1 = gost3410_2012_256_with_gost3411_2012_256
    // 2 = gost3410_2012_512_with_gost3411_2012_512
    SigA_NONE = 0,
    SigA_256  = 1,
    SigA_512  = 2
} SignatureAlg;

typedef struct
{
    char     name[MAX_NAME_LEN + 1];
    uint8_t* pubkey;
    uint16_t pubkey_len;
    uint8_t  alg;
    int      used;
} KeyStoreItem;

typedef struct GeneratedKeys
{
    EVP_PKEY* identity_private;
    EVP_PKEY* vko_private;
} GeneratedKeys;

uint64_t get_u64_be(const uint8_t* p);
void     put_u64_be(uint8_t* p, uint64_t v);
uint32_t get_u32_be(const uint8_t* p);
void     put_u32_be(uint8_t* p, uint32_t v);
uint16_t get_u16_be(const uint8_t* p);
void     put_u16_be(uint8_t* p, uint16_t v);

int  ossl_init_crypto(OSSL_PROVIDER** dflt, OSSL_PROVIDER** gost);
int  ossl_destroy_crypto(OSSL_PROVIDER** dflt, OSSL_PROVIDER** gost);
void ossl_print_error(const char* where);

int kb_clear(KeyBundle* kb);
int kb_free(KeyBundle* kb);

int key_to_der_pub(EVP_PKEY* key, uint8_t** out, uint16_t* out_len);
int der_to_key_pub(EVP_PKEY** out, uint8_t* in, uint16_t in_len);

int get_hash(FingerprintAlg fa, uint8_t* identity_pub, uint16_t identity_len, uint8_t** out,
             uint16_t* out_len);

int get_sign_kb(KeyBundle* kb, EVP_PKEY* private_key, unsigned char** out, size_t* out_len);

int verify_sign(KeyBundle* kb, EVP_PKEY* public_key);

int init_key_bundle(KeyBundle* kb, uint32_t client_id, EVP_PKEY* private_key,
                    const char* temp_user);
int pem_write_private_key(const char* path, EVP_PKEY* key);
int pem_write_public_key(const char* path, EVP_PKEY* key);

int pem_read_private_key(const char* path, EVP_PKEY** key);
int pem_read_public_key(const char* path, EVP_PKEY** key);

int der_write_private_key(const char* path, EVP_PKEY* key);
int der_read_public_key(const char* path, EVP_PKEY** key);

EVP_PKEY* generate_key(const char* name);
EVP_PKEY* generate_identity_key(void);
EVP_PKEY* generate_vko_key(void);

int create_keys(const char* name);

int serialize_key_bundle_to_sign(KeyBundle* kb, uint8_t** out, uint16_t* out_len);
int serialize_key_bundle_full(KeyBundle* kb, uint8_t** out, uint16_t* out_len);

KeyBundle* deserialize_key_bundle_full(const uint8_t* data, uint16_t data_len);

int verify_key_bundle(const uint8_t* data, uint16_t data_len);

int ensure_keys_dir(const char* name);

int read_private_keys(EVP_PKEY** out_identity, EVP_PKEY** out_vko, const char* name);
int get_info(uint32_t client_id_a, uint32_t client_id_b, uint8_t* fingerprint_a,
             uint8_t* fingerprint_b, uint16_t fingerprint_len, uint8_t* vko_pub_a,
             uint8_t* vko_pub_b, uint16_t vko_len, uint8_t** out, uint16_t* out_len);

int get_kdf(uint8_t* secret_key, uint16_t secret_key_len, const uint8_t* salt, uint16_t salt_len,
            uint8_t* info, uint16_t info_len, uint8_t* key, size_t keylen);

EVP_PKEY* get_key(const char* name, const char* key_name);
int derive_raw_secret(EVP_PKEY* my_vko_private, EVP_PKEY* peer, uint8_t** out, size_t* out_len);
int kuznechik_encrypt_room_key(uint8_t* nonce, uint8_t* enc_key, uint8_t* room_key,
                               int room_key_len, uint8_t* mac_key, uint8_t aad[AAD_LEN],
                               uint8_t** out, uint16_t* out_len, uint8_t** tag_out,
                               uint16_t* tag_out_len);
int build_aad(uint8_t aad[AAD_LEN], uint32_t sender_id, uint32_t to_client_id, uint32_t room_id,
              uint64_t epoch);

int kuznechik_decrypt_room_key(uint8_t* nonce, uint8_t* enc_key, uint8_t* encrypted_room_key,
                               int encrypted_room_key_len, uint8_t* mac_key, uint8_t aad[AAD_LEN],
                               uint8_t** out, uint16_t* out_len, uint8_t* tag_in,
                               uint16_t tag_in_len);
int kuznechik_decrypt_message(uint8_t* nonce, uint8_t* enc_key, uint8_t* msg, int msg_len,
                              uint8_t* mac_key, uint8_t aad[AAD_FOR_ENC_CHAT_LEN], uint8_t** out,
                              uint16_t* out_len, uint8_t* tag_in, uint16_t tag_in_len);
int validate_key_bundle_algorithms(KeyBundle* kb);
int kuznechik_encrypt_message(uint8_t* nonce, uint8_t* enc_key, uint8_t* msg, int msg_len,
                              uint8_t* mac_key, uint8_t aad[AAD_FOR_ENC_CHAT_LEN], uint8_t** out,
                              uint16_t* out_len, uint8_t** tag_out, uint16_t* tag_out_len);
int client_send_pkt_enc_chat(int epfd, Client* c, RoomSession* room, uint8_t* msg,
                             uint16_t msg_len);
int decrypt_chat_message(uint8_t* nonce, uint8_t room_key[ROOM_KEY_LEN], uint32_t sender_id,
                         uint32_t room_id, uint64_t epoch, uint64_t seq, uint8_t* msg,
                         uint16_t msg_len, uint8_t* tag, uint8_t** out_msg, uint16_t* out_msg_len);
int client_recv_pkt_enc_chat(Client* c, Header* h, RoomSession* room, uint8_t* msg,
                             uint16_t msg_len, uint8_t** out_msg, uint16_t* out_msg_len);
int server_send_challenge(int epfd, Client* c, uint32_t challenger_id, uint8_t* out_challenge,
                          uint32_t* message_id);
int file_exists(const char* path);
int client_response_challenge(int epfd, Client* c, uint8_t* msg, uint16_t msg_len,
                              EVP_PKEY* private_key);

int key_bundle_matches_ksi(Client* c, const uint8_t* data, uint16_t data_len);
int generate_keys_in_memory(GeneratedKeys* gk);
int save_keys_from_memory(const char* name, GeneratedKeys* gk);

int keys_exist(const char* name);
int verify_register_commit(uint32_t client_id, const char* name, uint8_t* nonce, uint8_t* msg,
                           uint16_t msg_len, EVP_PKEY** out_identity_pub);
int get_sign_register_commit(uint32_t client_id, const char* name, const uint8_t* nonce,
                             EVP_PKEY* private_key, const uint8_t* identity_pub_der,
                             uint16_t identity_pub_der_len, unsigned char** out, size_t* out_len);
int get_challenge(uint8_t challenge[CHALLENGE_LEN]);
#endif