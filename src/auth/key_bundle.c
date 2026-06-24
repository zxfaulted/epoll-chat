#include "client/client_commands.h"

#include "auth/auth.h"
#include "auth/key_bundle.h"
#include "client/client_send.h"
#include "crypto/crypto_core.h"
#include "crypto/ksi.h"
#include "e2e/client_room_session.h"
#include "e2e/room_crypto.h"
#include "protocol/message_id.h"
#include "protocol/pkt_build.h"
#include "storage/der_io.h"
#include "storage/pem_io.h"
#include "transport/epoll_io.h"
#include "transport/packet_io.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

int send_kb(Client* c, uint8_t* kb, uint16_t kb_len, uint32_t owner_id, uint32_t room_id,
            uint32_t* message_id)
{
    Header h     = {0};
    h.type       = PKT_ENC_KEY_BUNDLE;
    h.sender_id  = owner_id;
    h.room_id    = room_id;
    h.message_id = message_id ? next_message_id(message_id) : 0;
    h.timestamp  = (uint64_t)time(NULL);
    h.version    = 1;
    h.flags      = 0;

    if (enqueue_packet(c, &h, kb, kb_len) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        return -1;
    }
    return 0;
}

int kb_clear(KeyBundle* kb)
{
    if (!kb)
    {
        return -1;
    }

    OPENSSL_free(kb->fingerprint);
    OPENSSL_free(kb->identity_pub);
    OPENSSL_free(kb->signature);
    OPENSSL_free(kb->vko_pub);

    memset(kb, 0, sizeof(KeyBundle));
    return 0;
}

int kb_free(KeyBundle* kb)
{
    if (!kb)
    {
        return -1;
    }
    kb_clear(kb);
    free(kb);
    return 0;
}

int get_sign_kb(KeyBundle* kb, EVP_PKEY* private_key, unsigned char** out, size_t* out_len)
{
    int            ret     = -1;
    unsigned char* sigret  = NULL;
    size_t         siglen  = 0;
    EVP_MD*        md      = NULL;
    EVP_MD_CTX*    ctx     = NULL;
    uint8_t*       buf     = NULL;
    uint16_t       buf_len = 0;
    if (!kb || !private_key || !out || !out_len)
    {
        return -1;
    }
    *out     = NULL;
    *out_len = 0;

    md = EVP_MD_fetch(NULL, "md_gost12_512", NULL);
    if (!md)
    {
        goto cleanup;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        goto cleanup;
    }

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, private_key) <= 0)
    {
        ossl_print_error("EVP_DigestSignInit failed");
        goto cleanup;
    }

    if (serialize_key_bundle_to_sign(kb, &buf, &buf_len) < 0)
    {
        fprintf(stderr, "serialize_key_bundle_to_sign failed\n");
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, buf, buf_len) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, NULL, &siglen) <= 0)
    {
        ossl_print_error("EVP_DigestSignFinal failed");
        goto cleanup;
    }
    sigret = OPENSSL_malloc(siglen);
    if (!sigret)
    {
        ossl_print_error("OPENSSL_malloc failed");
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, sigret, &siglen) <= 0)
    {
        ossl_print_error("EVP_DigestSignFinal failed");
        goto cleanup;
    }
    *out     = sigret;
    *out_len = siglen;
    sigret   = NULL;
    ret      = 0;
cleanup:
    OPENSSL_free(buf);
    OPENSSL_free(sigret);
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);

    return ret;
}

int init_key_bundle(KeyBundle* kb, uint32_t client_id, EVP_PKEY* private_key, const char* temp_user)
{
    if (!kb || !private_key)
    {
        return -1;
    }
    memset(kb, 0, sizeof(*kb));

    int ret = 0;

    EVP_PKEY* identity_pub_evp     = NULL;
    uint8_t*  identity_pub_der     = NULL;
    identity_pub_der               = NULL;
    EVP_PKEY*      vko_pub_evp     = NULL;
    uint16_t       vko_pub_len     = 0;
    uint8_t*       vko_pub_der     = NULL;
    uint8_t*       fingerprint     = NULL;
    uint16_t       fingerprint_len = 0;
    unsigned char* signature       = NULL;
    size_t         signature_len   = 0;

    kb->bundle_version = 1;
    kb->client_id      = client_id;
    char path[256];
    snprintf(path, sizeof(path), "./keys/%s/identity_public.pem", temp_user);
    pem_read_public_key(path, &identity_pub_evp);
    if (identity_pub_evp == NULL)
    {
        fprintf(stderr, "[ERROR] pem_read_public_key FAULTED");
        ret = -1;
        goto cleanup;
    }
    kb->identity_alg          = IKA_GOST2012_512;
    uint16_t identity_pub_len = 0;
    if (key_to_der_pub(identity_pub_evp, &identity_pub_der, &identity_pub_len) < 0)
    {
        fprintf(stderr, "[ERROR] key_to_der_pub  FAULTED");
        ret = -1;
        goto cleanup;
    }
    kb->identity_pub     = identity_pub_der;
    kb->identity_pub_len = identity_pub_len;
    identity_pub_der     = NULL;

    kb->vko_alg = VKO_GOST2012_512;
    snprintf(path, sizeof(path), "./keys/%s/vko_public.pem", temp_user);
    pem_read_public_key(path, &vko_pub_evp);
    if (vko_pub_evp == NULL)
    {
        fprintf(stderr, "[ERROR] pem_read_public_key FAULTED");
        ret = -1;
        goto cleanup;
    }
    if (key_to_der_pub(vko_pub_evp, &vko_pub_der, &vko_pub_len) < 0)
    {
        fprintf(stderr, "[ERROR] key_to_der_pub  FAULTED");
        ret = -1;
        goto cleanup;
    }
    kb->vko_pub_len    = vko_pub_len;
    kb->vko_pub        = vko_pub_der;
    vko_pub_der        = NULL;
    kb->vko_expires_at = (uint64_t)time(NULL) + VKO_TTL_SECONDS;

    kb->fingerprint_alg = FA_GOST2012_512;
    if (get_hash(FA_GOST2012_512, kb->identity_pub, kb->identity_pub_len, &fingerprint,
                 &fingerprint_len) < 0)
    {
        fprintf(stderr, "[ERROR] get_fingerprint FAULTED");
        ret = -1;
        goto cleanup;
    }
    kb->fingerprint_len = fingerprint_len;
    kb->fingerprint     = fingerprint;
    fingerprint         = NULL;

    kb->signature_alg = SigA_512;
    if (get_sign_kb(kb, private_key, &signature, &signature_len) < 0)
    {
        fprintf(stderr, "[ERROR] get_sign_kb FAULTED");
        ret = -1;
        goto cleanup;
    }
    if (signature_len > UINT16_MAX)
    {
        fprintf(stderr, "[ERROR] signature_len too large\n");
        ret = -1;
        goto cleanup;
    }
    kb->signature     = (uint8_t*)signature;
    signature         = NULL;
    kb->signature_len = (uint16_t)signature_len;

cleanup:

    EVP_PKEY_free(identity_pub_evp);
    OPENSSL_free(identity_pub_der);
    EVP_PKEY_free(vko_pub_evp);
    OPENSSL_free(vko_pub_der);

    if (ret < 0)
    {
        kb_clear(kb);
    }
    return ret;
}

int serialize_key_bundle_to_sign(KeyBundle* kb, uint8_t** out, uint16_t* out_len)
{
    if (!kb || !out || !out_len)
    {
        return -1;
    }

    int ret = -1;

    uint8_t* buf = NULL;
    size_t   len = 0;
    *out         = NULL;
    *out_len     = 0;

    len += 1; // bundle version
    len += 4; // client_id

    len += 1;                    // identity_alg
    len += 2;                    // identity_pub_len
    len += kb->identity_pub_len; // identity_pub

    len += 1;               // vko_alg
    len += 2;               // vko_pub_len
    len += kb->vko_pub_len; // vko_pub
    len += 8;               // vko_expires_at

    len += 1; // fingerprint_alg
    len += 2; // fingerprint_len
    len += kb->fingerprint_len;

    len += 1; // signature_alg

    if (len > UINT16_MAX)
    {
        fprintf(stderr, "serialized bundle too large\n");
        goto cleanup;
    }
    buf = OPENSSL_malloc(len);
    if (!buf)
    {
        ossl_print_error("OPENSSL_malloc failed");
        goto cleanup;
    }
    uint8_t* p = buf;
    *p++       = (uint8_t)kb->bundle_version;

    put_u32_be(p, kb->client_id);
    p += 4;

    // identity
    if (!kb->identity_pub || kb->identity_pub_len == 0)
    {
        fprintf(stderr, "identity_pub bad\n");
        goto cleanup;
    }

    *p++ = (uint8_t)kb->identity_alg;

    put_u16_be(p, kb->identity_pub_len);
    p += 2;

    memcpy(p, kb->identity_pub, kb->identity_pub_len);
    p += kb->identity_pub_len;

    // vko
    if (!kb->vko_pub || kb->vko_pub_len <= 0)
    {
        fprintf(stderr, "vko_pub bad\n");
        goto cleanup;
    }

    *p++ = (uint8_t)kb->vko_alg;

    put_u16_be(p, kb->vko_pub_len);
    p += 2;

    memcpy(p, kb->vko_pub, kb->vko_pub_len);
    p += kb->vko_pub_len;

    put_u64_be(p, kb->vko_expires_at);
    p += 8;

    // fingerprint
    if (!kb->fingerprint || kb->fingerprint_len == 0)
    {
        fprintf(stderr, "fingerprint bad\n");
        goto cleanup;
    }

    *p++ = (uint8_t)kb->fingerprint_alg;

    put_u16_be(p, kb->fingerprint_len);
    p += 2;

    memcpy(p, kb->fingerprint, kb->fingerprint_len);
    p += kb->fingerprint_len;

    // signature
    *p++ = (uint8_t)kb->signature_alg;

    if ((size_t)(p - buf) != len)
    {
        fprintf(stderr, "serialized buf len mismatch\n");
        goto cleanup;
    }
    *out     = buf;
    *out_len = (uint16_t)len;
    buf      = NULL;
    p        = NULL;

    ret = 0;
cleanup:
    OPENSSL_free(buf);
    return ret;
}

int serialize_key_bundle_full(KeyBundle* kb, uint8_t** out, uint16_t* out_len)
{
    if (!kb || !out || !out_len)
    {
        return -1;
    }

    int ret = -1;

    uint8_t* buf = NULL;
    size_t   len = 0;
    *out         = NULL;
    *out_len     = 0;

    len += 1; // bundle version
    len += 4; // client_id

    len += 1;                    // identity_alg
    len += 2;                    // identity_pub_len
    len += kb->identity_pub_len; // identity_pub

    len += 1;               // vko_alg
    len += 2;               // vko_pub_len
    len += kb->vko_pub_len; // vko_pub
    len += 8;               // vko_expires_at

    len += 1; // fingerprint_alg
    len += 2; // fingerprint_len
    len += kb->fingerprint_len;

    len += 1; // signature_alg
    len += 2; // signature_len
    len += kb->signature_len;

    if (len > UINT16_MAX)
    {
        fprintf(stderr, "serialized bundle too large\n");
        goto cleanup;
    }
    buf = OPENSSL_malloc(len);
    if (!buf)
    {
        ossl_print_error("OPENSSL_malloc failed");
        goto cleanup;
    }
    uint8_t* p = buf;
    *p++       = (uint8_t)kb->bundle_version;

    put_u32_be(p, kb->client_id);
    p += 4;

    // identity
    if (!kb->identity_pub || kb->identity_pub_len == 0)
    {
        fprintf(stderr, "identity_pub bad\n");
        goto cleanup;
    }

    *p++ = (uint8_t)kb->identity_alg;

    put_u16_be(p, kb->identity_pub_len);
    p += 2;

    memcpy(p, kb->identity_pub, kb->identity_pub_len);
    p += kb->identity_pub_len;

    // vko
    if (!kb->vko_pub || kb->vko_pub_len <= 0)
    {
        fprintf(stderr, "vko_pub bad\n");
        goto cleanup;
    }

    *p++ = (uint8_t)kb->vko_alg;

    put_u16_be(p, kb->vko_pub_len);
    p += 2;

    memcpy(p, kb->vko_pub, kb->vko_pub_len);
    p += kb->vko_pub_len;

    put_u64_be(p, kb->vko_expires_at);
    p += 8;

    // fingerprint
    if (!kb->fingerprint || kb->fingerprint_len == 0)
    {
        fprintf(stderr, "fingerprint bad\n");
        goto cleanup;
    }

    *p++ = (uint8_t)kb->fingerprint_alg;

    put_u16_be(p, kb->fingerprint_len);
    p += 2;

    memcpy(p, kb->fingerprint, kb->fingerprint_len);
    p += kb->fingerprint_len;

    // signature
    if (!kb->signature || kb->signature_len == 0)
    {
        fprintf(stderr, "signature bad\n");
        goto cleanup;
    }

    *p++ = (uint8_t)kb->signature_alg;

    put_u16_be(p, kb->signature_len);
    p += 2;

    memcpy(p, kb->signature, kb->signature_len);
    p += kb->signature_len;

    if ((size_t)(p - buf) != len)
    {
        fprintf(stderr, "serialized buf len mismatch\n");
        goto cleanup;
    }
    *out     = buf;
    *out_len = (uint16_t)len;
    buf      = NULL;
    p        = NULL;

    ret = 0;
cleanup:
    OPENSSL_free(buf);
    return ret;
}

KeyBundle* deserialize_key_bundle_full(const uint8_t* data, uint16_t data_len)
{
    KeyBundle* kb = calloc(1, sizeof(KeyBundle));
    if (!kb)
    {
        return NULL;
    }
    KeyBundle* ret = NULL;

    const uint8_t* p   = data;
    const uint8_t* end = data + data_len;

    NEED(p, end, 1);
    kb->bundle_version = *p++;

    NEED(p, end, 4);
    kb->client_id = get_u32_be(p);
    p += 4;

    // identity
    NEED(p, end, 1);
    kb->identity_alg = *p++;

    NEED(p, end, 2);
    kb->identity_pub_len = get_u16_be(p);
    p += 2;

    if (kb->identity_pub_len == 0)
    {
        fprintf(stderr, "identity_pub_len bad\n");
        goto cleanup;
    }

    NEED(p, end, kb->identity_pub_len);
    kb->identity_pub = OPENSSL_malloc(kb->identity_pub_len);
    if (!kb->identity_pub)
    {
        fprintf(stderr, "identity_pub bad\n");
        goto cleanup;
    }
    memcpy(kb->identity_pub, p, kb->identity_pub_len);
    p += kb->identity_pub_len;

    // vko
    NEED(p, end, 1);
    kb->vko_alg = (uint8_t)*p++;

    NEED(p, end, 2);
    kb->vko_pub_len = get_u16_be(p);
    p += 2;

    if (kb->vko_pub_len == 0)
    {
        fprintf(stderr, "vko_pub_len bad\n");
        goto cleanup;
    }

    NEED(p, end, kb->vko_pub_len);
    kb->vko_pub = OPENSSL_malloc(kb->vko_pub_len);
    if (!kb->vko_pub)
    {
        fprintf(stderr, "vko_pub bad\n");
        goto cleanup;
    }
    memcpy(kb->vko_pub, p, kb->vko_pub_len);
    p += kb->vko_pub_len;

    NEED(p, end, 8);
    kb->vko_expires_at = get_u64_be(p);
    p += 8;

    // fingerprint
    NEED(p, end, 1);
    kb->fingerprint_alg = *p++;

    NEED(p, end, 2);
    kb->fingerprint_len = get_u16_be(p);
    p += 2;
    if (kb->fingerprint_len == 0)
    {
        fprintf(stderr, "fingerprint_len bad\n");
        goto cleanup;
    }

    NEED(p, end, kb->fingerprint_len);
    kb->fingerprint = OPENSSL_malloc(kb->fingerprint_len);
    if (!kb->fingerprint)
    {
        fprintf(stderr, "fingerprint bad\n");
        goto cleanup;
    }
    memcpy(kb->fingerprint, p, kb->fingerprint_len);
    p += kb->fingerprint_len;

    // signature
    NEED(p, end, 1);
    kb->signature_alg = *p++;

    NEED(p, end, 2);
    kb->signature_len = get_u16_be(p);
    p += 2;

    if (kb->signature_len == 0)
    {
        fprintf(stderr, "signature_len bad\n");
        goto cleanup;
    }

    NEED(p, end, kb->signature_len);
    kb->signature = OPENSSL_malloc(kb->signature_len);
    if (!kb->signature)
    {
        ossl_print_error("OPENSSL_malloc failed");
        goto cleanup;
    }
    memcpy(kb->signature, p, kb->signature_len);
    p += kb->signature_len;

    if (p != end)
    {
        fprintf(stderr, "extra bytes in bundle\n");
        goto cleanup;
    }

    ret = kb;
cleanup:
    if (!ret)
    {
        kb_free(kb);
    }

    return ret;
}

int verify_key_bundle(const uint8_t* data, uint16_t data_len)
{
    if (!data)
    {
        return -1;
    }

    int        ret        = -1;
    KeyBundle* kb         = NULL;
    EVP_PKEY*  public_key = NULL;
    uint8_t*   hash       = NULL;
    uint16_t   hash_len   = 0;

    // 1. deserialize_key_bundle_full
    kb = deserialize_key_bundle_full(data, data_len);
    if (!kb)
    {
        fprintf(stderr, "deserialize_key_bundle_full failed\n");
        goto cleanup;
    }
    // 2. проверить bundle_version
    if (kb->bundle_version != 1)
    {
        fprintf(stderr, "wrong bundle version\n");
        goto cleanup;
    }
    // 3. проверить identity_alg, vko_alg, fingerprint_alg, signature_alg
    if (validate_key_bundle_algorithms(kb) < 0)
    {
        fprintf(stderr, "wrong key bundle algorithms\n");
        goto cleanup;
    }
    // 4. проверить vko_expires_at > time(NULL)
    if (kb->vko_expires_at <= (uint64_t)time(NULL))
    {
        fprintf(stderr, "vko expired\n");
        goto cleanup;
    }
    // 5. пересчитать fingerprint от identity_pub
    if (get_hash(kb->fingerprint_alg, kb->identity_pub, kb->identity_pub_len, &hash, &hash_len) < 0)
    {
        fprintf(stderr, "fingerprint: get_hash failed\n");
        goto cleanup;
    }
    if (kb->fingerprint_len != hash_len)
    {
        fprintf(stderr, "fingerprint len mismatch\n");
        goto cleanup;
    }
    // 6. сравнить с kb->fingerprint
    if (memcmp(kb->fingerprint, hash, kb->fingerprint_len) != 0)
    {
        fprintf(stderr, "fingerprint is wrong\n");
        goto cleanup;
    }
    // // 7. найти name в keystore
    // int idx = find_in_key_store(items, items_len, name);
    // if (idx < 0)
    // {
    //     goto cleanup;
    // }
    // // 8. сравнить identity_pub из bundle с identity_pub из keystore
    // if (items[idx].pubkey_len != kb->identity_pub_len ||
    //     memcmp(items[idx].pubkey, kb->identity_pub, kb->identity_pub_len) != 0)
    // {
    //     fprintf(stderr, "pubkey is wrong for this name\n");
    //     goto cleanup;
    // }

    // 9. der_to_key_pub(identity_pub)
    if (der_to_key_pub(&public_key, kb->identity_pub, kb->identity_pub_len) < 0)
    {
        fprintf(stderr, "der_to_key_pub failed\n");
        goto cleanup;
    }
    if (!public_key)
    {
        fprintf(stderr, "der_to_key_pub failed\n");
        goto cleanup;
    }
    // 10. verify_sign(kb, identity_pub_key)
    ret = verify_sign(kb, public_key);
cleanup:
    if (kb)
    {
        kb_free(kb);
    }
    EVP_PKEY_free(public_key);
    OPENSSL_free(hash);
    return ret;
}

int validate_key_bundle_algorithms(KeyBundle* kb)
{
    if (kb->vko_alg != VKO_GOST2012_512)
    {
        return -1;
    }
    if (kb->identity_alg != IKA_GOST2012_512)
    {
        return -1;
    }
    if (kb->signature_alg != SigA_512)
    {
        return -1;
    }
    if (kb->fingerprint_alg != FA_GOST2012_512)
    {
        return -1;
    }
    return 0;
}

// 1 matches
// 0 not
int key_bundle_matches_ksi(Client* c, const uint8_t* data, uint16_t data_len)
{
    if (!c || !data || data_len == 0)
        return -1;

    int ret = 0;

    KeyBundle* kb                 = NULL;
    EVP_PKEY*  registered_pub     = NULL;
    uint8_t*   registered_der     = NULL;
    uint16_t   registered_der_len = 0;

    kb = deserialize_key_bundle_full(data, data_len);
    if (!kb)
        goto cleanup;

    if (kb->client_id != c->id)
    {
        fprintf(stderr, "bundle client_id mismatch\n");
        goto cleanup;
    }

    registered_pub = ksi_read_key(c->name);
    if (!registered_pub)
        goto cleanup;

    if (key_to_der_pub(registered_pub, &registered_der, &registered_der_len) < 0)
        goto cleanup;

    if (kb->identity_pub_len != registered_der_len)
    {
        fprintf(stderr, "identity key len mismatch\n");
        goto cleanup;
    }

    if (CRYPTO_memcmp(kb->identity_pub, registered_der, registered_der_len) != 0)
    {
        fprintf(stderr, "identity key mismatch\n");
        goto cleanup;
    }

    ret = 1;

cleanup:
    kb_free(kb);
    EVP_PKEY_free(registered_pub);
    OPENSSL_free(registered_der);
    return ret;
}

int handle_kb(int epfd, uint8_t* data, uint16_t data_len, KeyBundle* my_kb,
              EVP_PKEY* my_vko_private, PeerWrapSession* peers, size_t peers_count,
              RoomSession* rooms, size_t rooms_count, UserEntry* ue, Client* c)
{
    if (!data || !my_kb || !peers || !rooms || !c)
    {
        return -1;
    }
    int        ret      = -1;
    KeyBundle* kb       = NULL;
    uint8_t*   info     = NULL;
    uint16_t   info_len = 0;
    uint8_t    wrapping_key[WRAPPING_KEY_LEN];
    EVP_PKEY*  peer_vko_pub   = NULL;
    uint8_t*   raw_secret     = NULL;
    size_t     raw_secret_len = 0;

    if (verify_key_bundle(data, data_len) != 1)
    {
        fprintf(stderr, "verify_key_bundle failed\n");
        return -1;
    }

    kb = deserialize_key_bundle_full(data, data_len);
    if (!kb)
    {
        fprintf(stderr, "deserialize_key_bundle_full failed\n");
        goto cleanup;
    }

    if (kb->client_id == my_kb->client_id)
    {
        ret = 0;
        goto cleanup;
    }

    if (my_kb->fingerprint_len != kb->fingerprint_len)
    {
        fprintf(stderr, "fingerprint len mismatch\n");
        goto cleanup;
    }

    if (my_kb->vko_pub_len != kb->vko_pub_len)
    {
        fprintf(stderr, "vko_pub_len mismatch\n");
        goto cleanup;
    }
    if (der_to_key_pub(&peer_vko_pub, kb->vko_pub, kb->vko_pub_len) < 0 || !peer_vko_pub)
    {
        fprintf(stderr, "der_to_key_pub failed\n");
        goto cleanup;
    }

    if (derive_raw_secret(my_vko_private, peer_vko_pub, &raw_secret, &raw_secret_len) < 0)
    {
        fprintf(stderr, "derive_raw_secret failed\n");
        goto cleanup;
    }

    if (get_info(my_kb->client_id, kb->client_id, my_kb->fingerprint, kb->fingerprint,
                 my_kb->fingerprint_len, my_kb->vko_pub, kb->vko_pub, my_kb->vko_pub_len, &info,
                 &info_len) < 0)
    {
        fprintf(stderr, "get_info failed\n");
        goto cleanup;
    }

    if (raw_secret_len > UINT16_MAX)
    {
        fprintf(stderr, "raw_secret_len is too large\n");
        goto cleanup;
    }
    const unsigned char salt[] = "chat_v1";
    if (get_kdf(raw_secret, (uint16_t)raw_secret_len, salt, (uint16_t)(sizeof(salt) - 1), info,
                info_len, wrapping_key, sizeof(wrapping_key)) < 0)
    {
        fprintf(stderr, "get_kdf failed\n");
        goto cleanup;
    }

    if (save_peer_wrap_session(peers, peers_count, kb->client_id, kb->fingerprint,
                               kb->fingerprint_len, wrapping_key) < 0)
    {
        fprintf(stderr, "get_kdf failed\n");
        goto cleanup;
    }
    printf("[E2E] saved wrapping key for peer#%" PRIu32 "\n", kb->client_id);

    if (c->room_state == ROOM_READY && user_entry_exists(ue, kb->client_id) &&
        am_room_leader(c, ue))
    {
        RoomSession* room = get_room_session(rooms, rooms_count, c->room_id);

        if (room)
        {
            if (send_room_key_to_peer(epfd, c, kb->client_id, wrapping_key, room) < 0)
            {
                fprintf(stderr, "send_room_key_to_peer failed\n");
                goto cleanup;
            }

            if (set_epollout_to_client(epfd, c) < 0)
            {
                fprintf(stderr, "set_epollout_to_client failed\n");
                goto cleanup;
            }

            printf("[E2E] I am leader. Sent room key to peer#%" PRIu32 ", epoch=%" PRIu64 "\n",
                   kb->client_id, get_room_epoch(room));
        }
    }
    ret = 0;

cleanup:
    if (raw_secret)
    {
        OPENSSL_cleanse(raw_secret, raw_secret_len);
        OPENSSL_free(raw_secret);
    }
    kb_free(kb);
    EVP_PKEY_free(peer_vko_pub);
    OPENSSL_free(info);
    OPENSSL_cleanse(wrapping_key, sizeof(wrapping_key));
    return ret;
}

// возвращает
// 1 правильная подпись
// 0 неправильная
// все остальное - ошибка
int verify_sign(KeyBundle* kb, EVP_PKEY* public_key)
{
    if (!kb || !public_key)
    {
        return -1;
    }

    int         ret      = -1;
    EVP_MD*     md       = NULL;
    EVP_MD_CTX* ctx      = NULL;
    uint8_t*    data     = NULL;
    uint16_t    data_len = 0;

    md = EVP_MD_fetch(NULL, "md_gost12_512", NULL);
    if (!md)
    {
        ossl_print_error("EVP_MD_fetch");
        goto cleanup;
    }
    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_MD_CTX_new\n");
        goto cleanup;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, public_key) <= 0)
    {
        fprintf(stderr, "EVP_DigestVerifyInit failed\n");
        goto cleanup;
    }

    if (serialize_key_bundle_to_sign(kb, &data, &data_len) < 0)
    {
        fprintf(stderr, "serialize_key_bundle_to_sign failed\n");
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, data, data_len) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    int rc = EVP_DigestVerifyFinal(ctx, kb->signature, kb->signature_len);
    if (rc == 1)
    {
        ret = 1;
    }
    else if (rc == 0)
    {
        ret = 0;
    }
    else
    {
        ossl_print_error("EVP_DigestVerifyFinal failed\n");
        goto cleanup;
    }

cleanup:
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(data);
    return ret;
}