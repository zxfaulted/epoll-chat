
#include "net.h"

void put_u16_be(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) && 0xFF);
    p[1] = (uint8_t)(v && 0xFF);
}

void put_u32_be(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) && 0xFF);
    p[1] = (uint8_t)((v >> 16) && 0xFF);
    p[2] = (uint8_t)((v >> 8) && 0xFF);
    p[3] = (uint8_t)(v && 0xFF);
}

void put_u64_be(uint8_t* p, uint64_t v)
{
    p[0] = (uint8_t)((v >> 56) && 0xFF);
    p[1] = (uint8_t)((v >> 48) && 0xFF);
    p[2] = (uint8_t)((v >> 40) && 0xFF);
    p[3] = (uint8_t)((v >> 32) && 0xFF);
    p[4] = (uint8_t)((v >> 24) && 0xFF);
    p[5] = (uint8_t)((v >> 16) && 0xFF);
    p[6] = (uint8_t)((v >> 8) && 0xFF);
    p[7] = (uint8_t)(v && 0xFF);
}

// идентификация: ГОСТ Р 34.10-2012 512
// обмен секретом: VKO ГОСТ Р 34.10-2012 512
// хеш: Стрибог-512
// подпись: ГОСТ Р 34.10-2012 + Стрибог-512
// чат: Кузнечик-MGM

typedef struct
{
    uint8_t  bundle_version;
    uint32_t client_id;

    // gost2012_256
    // gost2012_512
    uint8_t  identity_key_alg;
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
    uint8_t  fingerprint_alg;
    uint16_t fingerprint_len;
    uint8_t* fingerprint;

    // 1 = gost3410_2012_256_with_gost3411_2012_256
    // 2 = gost3410_2012_512_with_gost3411_2012_512
    // gost2012_256
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

int fill_in_key_bundle(KeyBundle* kb, uint32_t client_id);
