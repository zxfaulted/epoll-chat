#ifndef CRYPTO_H
#define CRYPTO_H
#include "connection.h"
#include "crypto_core.h"
#include "protocol.h"
#include "room.h"
#include "types.h"
#include "wire.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

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

int get_hash(FingerprintAlg fa, uint8_t* identity_pub, uint16_t identity_len, uint8_t** out,
             uint16_t* out_len);

int create_keys(const char* name);

int read_private_keys(EVP_PKEY** out_identity, EVP_PKEY** out_vko, const char* name);
int get_info(uint32_t client_id_a, uint32_t client_id_b, uint8_t* fingerprint_a,
             uint8_t* fingerprint_b, uint16_t fingerprint_len, uint8_t* vko_pub_a,
             uint8_t* vko_pub_b, uint16_t vko_len, uint8_t** out, uint16_t* out_len);

EVP_PKEY* get_key(const char* name, const char* key_name);

int build_aad(uint8_t aad[AAD_LEN], uint32_t sender_id, uint32_t to_client_id, uint32_t room_id,
              uint64_t epoch);

int client_send_pkt_enc_chat(int epfd, Client* c, RoomSession* room, uint8_t* msg,
                             uint16_t msg_len);
int client_recv_pkt_enc_chat(Client* c, Header* h, RoomSession* room, uint8_t* msg,
                             uint16_t msg_len, uint8_t** out_msg, uint16_t* out_msg_len);
int file_exists(const char* path);

int generate_keys_in_memory(GeneratedKeys* gk);
int save_keys_from_memory(const char* name, GeneratedKeys* gk);

int  keys_exist(const char* name);
int  handle_room_key(Client* c, PeerWrapSession* peers, RoomSession* rooms, Header* h, uint8_t* msg,
                     uint16_t msg_len);
void clear_generated_keys(GeneratedKeys* gk);
int  load_keys_for_name(GeneratedKeys* gk, const char* user_name);
int  key_bundle_matches_ksi(Client* c, const uint8_t* data, uint16_t data_len);
int  ensure_keys_dir(const char* name);

#endif