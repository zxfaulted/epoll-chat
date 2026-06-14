#include "auth.h"
#include "connection.h"
#include "crypto.h"
#include "der_io.h"
#include "ksi.h"
#include "net.h"
#include "transport.h"
#include <string.h>

int get_challenge(uint8_t challenge[CHALLENGE_LEN])
{
    if (RAND_bytes(challenge, CHALLENGE_LEN) != 1)
    {
        ossl_print_error("RAND_bytes");
        return -1;
    }
    return 0;
}

// "chat_auth_v1" || client_id || username || challenge
int get_sign_challenge(uint32_t client_id, const char* name, uint8_t* msg, uint16_t msg_len,
                       EVP_PKEY* private_key, unsigned char** out, size_t* out_len)
{
    if (!msg || !private_key || !out || !out_len || msg_len != (4 + CHALLENGE_LEN))
    {
        return -1;
    }
    int            ret    = -1;
    unsigned char* sigret = NULL;
    size_t         siglen = 0;
    EVP_MD*        md     = NULL;
    EVP_MD_CTX*    ctx    = NULL;
    uint8_t*       buf    = NULL;
    uint8_t*       p      = NULL;
    size_t         off    = 0;

    *out     = NULL;
    *out_len = 0;

    p                      = msg;
    uint32_t challenged_id = get_u32_be(p + off);
    if (challenged_id != client_id)
    {
        fprintf(stderr, "client id and challenge id are different\n");
        goto cleanup;
    }
    off += 4;

    uint8_t* challenge = p + off;

    md = EVP_MD_fetch(NULL, "md_gost12_512", NULL);
    if (!md)
    {
        ossl_print_error("EVP_MD_fetch");
        goto cleanup;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_MD_CTX_new");
        goto cleanup;
    }

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, private_key) <= 0)
    {
        ossl_print_error("EVP_DigestSignInit failed");
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, "chat_auth_v1", 12) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    uint8_t id_buf_be[4];
    put_u32_be(id_buf_be, client_id);

    if (EVP_DigestSignUpdate(ctx, id_buf_be, sizeof(id_buf_be)) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, name, strlen(name)) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, challenge, CHALLENGE_LEN) <= 0)
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

// возвращает
// 1 правильная подпись
// 0 неправильная
// все остальное - ошибка
// "chat_auth_v1" || client_id || username || challenge
int server_verify_challenge(Client* c, uint8_t* msg, uint16_t msg_len)
{
    if (!c || !msg)
    {
        return -1;
    }

    if (!ksi_exists(c->name))
    {
        return -1;
    }
    EVP_PKEY* public_key = NULL;

    public_key = ksi_read_key(c->name);
    if (!public_key)
    {
        fprintf(stderr, "ksi_read_key failed\n");
        return -1;
    }

    int         ret  = -1;
    EVP_MD*     md   = NULL;
    EVP_MD_CTX* ctx  = NULL;
    uint8_t*    data = NULL;

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

    if (EVP_DigestVerifyUpdate(ctx, "chat_auth_v1", 12) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    uint8_t id_buf_be[4];
    put_u32_be(id_buf_be, c->id);
    if (EVP_DigestVerifyUpdate(ctx, id_buf_be, sizeof(id_buf_be)) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, c->name, strlen(c->name)) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, c->challenge, CHALLENGE_LEN) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    int rc = EVP_DigestVerifyFinal(ctx, msg, msg_len);
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
    EVP_PKEY_free(public_key);
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(data);
    return ret;
}

// PKT_AUTH_CHALLENGE
// [4 client_id]
// [32 random_nonce]
int server_send_challenge(int epfd, Client* c, uint32_t challenger_id, uint8_t* out_challenge,
                          uint32_t* message_id)
{
    uint8_t challenge[32];
    uint8_t payload[36];

    put_u32_be(payload, challenger_id);

    if (RAND_bytes(challenge, 32) != 1)
    {
        ossl_print_error("RAND_bytes failed");
        return -1;
    }
    memcpy(payload + 4, challenge, 32);

    Header h     = {0};
    h.flags      = 0;
    h.message_id = next_message_id(message_id);
    h.room_id    = 0;
    h.sender_id  = SERVER_ID;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_AUTH_CHALLENGE;
    h.version    = 1;

    if (enqueue_packet(c, &h, payload, 36) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        return -1;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        fprintf(stderr, "set_epollout_to_client failed\n");
        return -1;
    }
    memcpy(out_challenge, challenge, 32);

    return 0;
}

// "chat_auth_v1" || client_id || name || nonce || identity_pub_der
int get_sign_register_commit(uint32_t client_id, const char* name, const uint8_t* nonce,
                             EVP_PKEY* private_key, const uint8_t* identity_pub_der,
                             uint16_t identity_pub_der_len, unsigned char** out, size_t* out_len)
{
    if (!private_key || !out || !out_len)
    {
        return -1;
    }
    int            ret    = -1;
    unsigned char* sigret = NULL;
    size_t         siglen = 0;
    EVP_MD*        md     = NULL;
    EVP_MD_CTX*    ctx    = NULL;
    uint8_t*       buf    = NULL;

    *out     = NULL;
    *out_len = 0;

    md = EVP_MD_fetch(NULL, "md_gost12_512", NULL);
    if (!md)
    {
        ossl_print_error("EVP_MD_fetch");
        goto cleanup;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_MD_CTX_new");
        goto cleanup;
    }

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, private_key) <= 0)
    {
        ossl_print_error("EVP_DigestSignInit failed");
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, "chat_register_v1", 16) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    uint8_t id_buf_be[4];
    put_u32_be(id_buf_be, client_id);

    if (EVP_DigestSignUpdate(ctx, id_buf_be, sizeof(id_buf_be)) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, name, strlen(name)) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, nonce, CHALLENGE_LEN) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }
    if (EVP_DigestSignUpdate(ctx, identity_pub_der, identity_pub_der_len) <= 0)
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

// [2 identity_pub_der_len]
// [identity_pub_der]
// [2 signature_len]
// [signature]
// "chat_auth_v1" || client_id || name || nonce || identity_pub_der
int verify_register_commit(uint32_t client_id, const char* name, uint8_t* nonce, uint8_t* msg,
                           uint16_t msg_len, EVP_PKEY** out_identity_pub)
{
    if (!name || !nonce || !msg || !out_identity_pub)
    {
        return -1;
    }
    int         ret                  = -1;
    EVP_MD*     md                   = NULL;
    EVP_MD_CTX* ctx                  = NULL;
    uint8_t*    buf                  = NULL;
    uint8_t*    p                    = NULL;
    size_t      off                  = 0;
    uint8_t*    identity_pub_der     = NULL;
    uint16_t    identity_pub_der_len = 0;
    uint8_t*    sig                  = NULL;
    uint16_t    siglen               = 0;
    EVP_PKEY*   public_key           = NULL;

    p = msg;
#define NEED_2(x)                                                                                  \
    do                                                                                             \
    {                                                                                              \
        if ((off > (size_t)msg_len) || ((size_t)(msg_len - off) < (size_t)(x)))                    \
        {                                                                                          \
            goto cleanup;                                                                          \
        }                                                                                          \
    } while (0)

    NEED_2(2);
    identity_pub_der_len = get_u16_be(p + off);
    off += 2;

    NEED_2(identity_pub_der_len);
    identity_pub_der = p + off;
    off += identity_pub_der_len;

    NEED_2(2);
    siglen = get_u16_be(p + off);
    off += 2;

    NEED_2(siglen);
    sig = p + off;
    off += siglen;

    if (off != msg_len)
    {
        fprintf(stderr, "msg_len wrong\n");
        return -1;
    }

    md = EVP_MD_fetch(NULL, "md_gost12_512", NULL);
    if (!md)
    {
        ossl_print_error("EVP_MD_fetch");
        goto cleanup;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_MD_CTX_new");
        goto cleanup;
    }

    if (der_to_key_pub(&public_key, identity_pub_der, identity_pub_der_len) < 0 || !public_key)
    {
        fprintf(stderr, "der_to_key_pub failed\n");
        goto cleanup;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, public_key) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyInit failed");
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, "chat_register_v1", 16) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    uint8_t id_buf_be[4];
    put_u32_be(id_buf_be, client_id);

    if (EVP_DigestVerifyUpdate(ctx, id_buf_be, sizeof(id_buf_be)) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, name, strlen(name)) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, nonce, CHALLENGE_LEN) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }
    if (EVP_DigestVerifyUpdate(ctx, identity_pub_der, identity_pub_der_len) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    int sigret = EVP_DigestVerifyFinal(ctx, sig, siglen);
    if (sigret == 0)
    {
        ret = 0;
        goto cleanup;
    }

    else if (sigret == 1)
    {
        ret = 1;
    }
    else
    {
        ret = -1;
        ossl_print_error("EVP_DigestVerifyFinal");
        goto cleanup;
    }
    *out_identity_pub = public_key;
    public_key        = NULL;
cleanup:
    OPENSSL_free(buf);
    EVP_PKEY_free(public_key);
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);

    return ret;
}

int add_pending_registration(PendingReg* pr, const char* name, uint8_t* challenge,
                             uint32_t client_id)
{
    int idx = find_in_pending_registrations(pr, name, client_id);
    if (idx >= 0)
    {
        if (pr[idx].expires_at > (uint64_t)time(NULL))
        {
            return -2;
        }
        else
        {
            pr[idx].used = 0;
        }
    }
    for (int i = 0; i < MAX_PENDING_REGISTRATIONS; i++)
    {
        if (!pr[i].used)
        {
            strncpy(pr[i].name, name, MAX_NAME_LEN + 1);
            if (challenge)
            {
                memcpy(pr[i].challenge, challenge, CHALLENGE_LEN);
            }
            pr[i].id         = client_id;
            pr[i].used       = 1;
            pr[i].expires_at = (uint64_t)time(NULL) + (uint64_t)60;
            return 0;
        }
    }
    return -1;
}

int find_in_pending_registrations(PendingReg* pr, const char* name, uint32_t client_id)
{
    for (int i = 0; i < MAX_PENDING_REGISTRATIONS; i++)
    {
        if (!pr[i].used)
        {
            continue;
        }
        if (strcmp(pr[i].name, name) != 0)
        {
            continue;
        }
        if (pr[i].expires_at <= (uint64_t)time(NULL))
        {
            pr[i].used = 0;
            continue;
        }
        if (pr[i].id != client_id)
        {
            continue;
        }
        return i;
    }
    return -1;
}

void remove_pending_registration(PendingReg* pr, const char* name, uint32_t client_id)
{
    for (int i = 0; i < MAX_PENDING_REGISTRATIONS; i++)
    {
        if (strcmp(pr[i].name, name) == 0 && pr[i].id == client_id)
        {
            pr[i].used = 0;
        }
    }
}

int server_send_registration_challenge(int epfd, Client* c, uint32_t client_id,
                                       const uint8_t challenge[CHALLENGE_LEN], uint32_t* message_id)
{
    if (!c || !message_id)
    {
        return -1;
    }
    uint8_t payload[4 + CHALLENGE_LEN];
    put_u32_be(payload, client_id);
    memcpy(payload + 4, challenge, CHALLENGE_LEN);

    Header h     = {0};
    h.version    = 1;
    h.type       = PKT_REGISTER_CHALLENGE;
    h.sender_id  = SERVER_ID;
    h.room_id    = 0;
    h.message_id = next_message_id(message_id);
    h.timestamp  = (uint64_t)time(NULL);

    if (enqueue_packet(c, &h, payload, sizeof(payload)) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        return -1;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        fprintf(stderr, "set_epollout_to_client failed\n");
        return -1;
    }
    return 0;
}