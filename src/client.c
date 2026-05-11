#include "crypto.h"
#include "net.h"
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

static RoomSession* get_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id)
{
    for (size_t i = 0; i < rooms_count; i++)
    {
        if (rooms[i].used && rooms[i].room_id == room_id)
        {
            return &rooms[i];
        }
    }
    return NULL;
}

static int save_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id,
                             uint64_t epoch, uint8_t room_key[ROOM_KEY_LEN])
{
    if (!rooms || !room_key)
    {
        return -1;
    }
    RoomSession* slot = NULL;

    for (size_t i = 0; i < rooms_count; i++)
    {
        if (rooms[i].used && rooms[i].room_id == room_id)
        {
            if (rooms[i].epoch > epoch)
            {
                return -1;
            }
            else if (rooms[i].epoch == epoch)
            {
                if (memcmp(rooms[i].room_key, room_key, ROOM_KEY_LEN) != 0)
                {
                    fprintf(stderr, "same epoch but wrong key\n");
                    return -1;
                }
                else
                {
                    return 0;
                }
            }
            else
            {
                slot = &rooms[i];
                break;
            }
        }
    }
    if (!slot)
    {
        for (size_t i = 0; i < rooms_count; i++)
        {
            if (!rooms[i].used)
            {
                slot = &rooms[i];
                break;
            }
        }
    }
    if (!slot)
    {
        return -1;
    }
    OPENSSL_cleanse(slot, sizeof(*slot));
    slot->room_id = room_id;
    slot->epoch   = epoch;
    memcpy(slot->room_key, room_key, ROOM_KEY_LEN);
    slot->send_seq = 1;
    slot->used     = 1;
    return 0;
}

static uint32_t room_leader_id(const Client* c, const UserEntry* ue)
{
    uint32_t leader_id;

    if (!c || c->id == 0)
    {
        return 0;
    }

    /*
      ue хранит других участников комнаты, но не самого клиента.
      Поэтому начинаем с собственного id.
    */
    leader_id = c->id;

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (!ue[i].used)
        {
            continue;
        }

        if (ue[i].id < leader_id)
        {
            leader_id = ue[i].id;
        }
    }

    return leader_id;
}

static int am_room_leader(const Client* c, const UserEntry* ue)
{
    if (!c || !ue || c->id == 0)
    {
        return 0;
    }

    return room_leader_id(c, ue) == c->id;
}

static int create_room_key(RoomSession* rooms, size_t count, uint32_t room_id)
{
    RoomSession* old_room   = get_room_session(rooms, count, room_id);
    uint64_t     next_epoch = old_room ? old_room->epoch + 1 : 1;
    uint8_t      key[ROOM_KEY_LEN];
    if (RAND_bytes(key, sizeof(key)) != 1)
    {
        ossl_print_error("RAND_bytes");
        return -1;
    }
    if (save_room_session(rooms, count, room_id, next_epoch, key) < 0)
    {
        OPENSSL_cleanse(key, sizeof(key));
        return -1;
    }

    OPENSSL_cleanse(key, sizeof(key));
    printf("[E2E] key added successfully for room #%" PRIu32 "\n", room_id);

    return 0;
}

// [4 to_client_id]
// [8 epoch]
// [16 nonce]
// [16 tag]
// [32 encrypted_room_key]
static int send_room_key_to_peer(Client* c, uint32_t peer_id, uint8_t* wrapping_key,
                                 RoomSession* room)
{
    if (!c || !wrapping_key || !room)
    {
        return -1;
    }

    uint8_t* cipher     = NULL;
    uint16_t cipher_len = 0;
    uint8_t* tag        = NULL;
    uint16_t tag_len    = 0;

    int     ret = -1;
    uint8_t buf[PKT_ENC_ROOM_KEY_PAYLOAD_LEN];

    uint8_t* p   = buf;
    size_t   off = 0;
    // [4 to_client_id]
    put_u32_be(p + off, peer_id);
    off += sizeof(peer_id);

    // [8 epoch]
    put_u64_be(p + off, room->epoch);
    off += sizeof(room->epoch);

    // [16 nonce]
    uint8_t* nonce = p + off;
    off += PKT_ENC_ROOM_KEY_NONCE_LEN;

    // [16 tag]
    uint8_t* tag_p = p + off;
    off += PKT_ENC_ROOM_KEY_TAG_LEN;

    // [32 encrypted_room_key]
    uint8_t* cipher_p = p + off;
    off += PKT_ENC_ROOM_KEY_CIPHERTEXT_LEN;

    if (RAND_bytes(nonce, PKT_ENC_ROOM_KEY_NONCE_LEN) != 1)
    {
        ossl_print_error("RAND_bytes");
        goto cleanup;
    }

    uint8_t mac_key[32];
    uint8_t enc_key[32];

    uint8_t aad[AAD_LEN];
    if (build_aad(aad, c->id, peer_id, room->room_id, room->epoch) < 0)
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

    if (kuznechik_encrypt_room_key(nonce, enc_key, room->room_key, ROOM_KEY_LEN, mac_key, aad,
                                   &cipher, &cipher_len, &tag, &tag_len) < 0)
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
    memcpy(cipher_p, cipher, cipher_len);
    memcpy(tag_p, tag, tag_len);

    Header h     = {0};
    h.flags      = 0;
    h.message_id = 0;
    h.room_id    = room->room_id;
    h.sender_id  = c->id;
    h.type       = PKT_ENC_ROOM_KEY;
    h.version    = 1;
    h.timestamp  = (uint64_t)time(NULL);

    if (enqueue_packet(c, &h, buf, sizeof(buf)) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        goto cleanup;
    }
    ret = 0;
cleanup:
    OPENSSL_cleanse(mac_key, 32);
    OPENSSL_cleanse(enc_key, 32);
    OPENSSL_free(cipher);
    OPENSSL_free(tag);

    return ret;
}

static PeerWrapSession* find_peer_wrap_session(PeerWrapSession* peers, size_t count,
                                               uint32_t peer_id)
{

    for (size_t i = 0; i < count; i++)
    {
        if (peers[i].used && peers[i].peer_id == peer_id)
        {
            return &peers[i];
        }
    }

    return NULL;
}

static int send_room_key_to_known_peers(int epfd, Client* c, PeerWrapSession* peers,
                                        size_t peers_count, RoomSession* rooms, size_t rooms_count,
                                        UserEntry* ue)
{
    RoomSession* room = get_room_session(rooms, rooms_count, c->room_id);

    if (!room)
    {
        fprintf(stderr, "no room session for current room\n");
        return -1;
    }

    int queued = 0;

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (!ue[i].used)
        {
            continue;
        }

        PeerWrapSession* peer = find_peer_wrap_session(peers, peers_count, ue[i].id);

        if (!peer)
        {
            continue;
        }

        if (send_room_key_to_peer(c, ue[i].id, peer->wrapping_key, room) < 0)
        {
            fprintf(stderr, "send_room_key_to_peer failed\n");
            return -1;
        }

        queued = 1;
        printf("[E2E] sent room key to peer#%" PRIu32 ", epoch=%" PRIu64 "\n", ue[i].id,
               room->epoch);
    }

    if (queued && set_epollout_to_client(epfd, c) < 0)
    {
        fprintf(stderr, "set_epollout_to_client failed\n");
        return -1;
    }

    return 0;
}

static int room_has_peers(const UserEntry* ue)
{
    if (!ue)
    {
        return 0;
    }

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (ue[i].used)
        {
            return 1;
        }
    }

    return 0;
}

static int rekey_current_room(int epfd, Client* c, PeerWrapSession* peers, size_t peers_count,
                              RoomSession* rooms, size_t rooms_count, UserEntry* ue)
{
    if (room_has_peers(ue) && !get_room_session(rooms, rooms_count, c->room_id))
    {
        fprintf(stderr, "[E2E] no old room key; cannot rekey safely\n");
        c->state = STATE_WAIT_ROOM_KEY;
        return 0;
    }

    if (create_room_key(rooms, rooms_count, c->room_id) < 0)
    {
        fprintf(stderr, "create_room_key failed\n");
        return -1;
    }

    if (send_room_key_to_known_peers(epfd, c, peers, peers_count, rooms, rooms_count, ue) < 0)
    {
        return -1;
    }

    c->state = STATE_READY;
    return 0;
}

static int user_entry_exists(const UserEntry* ue, uint32_t id)
{
    if (!ue)
    {
        return 0;
    }

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (ue[i].used && ue[i].id == id)
        {
            return 1;
        }
    }

    return 0;
}
static int rekey_current_room_as_leader(int epfd, Client* c, PeerWrapSession* peers,
                                        size_t peers_count, RoomSession* rooms, size_t rooms_count,
                                        UserEntry* ue)
{
    if (!am_room_leader(c, ue))
    {
        return 0;
    }

    return rekey_current_room(epfd, c, peers, peers_count, rooms, rooms_count, ue);
}

static RoomSession* find_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id)
{
    for (size_t i = 0; i < rooms_count; i++)
    {
        if (rooms[i].used && rooms[i].room_id == room_id)
        {
            return &rooms[i];
        }
    }
    return NULL;
}

static int save_peer_wrap_session(PeerWrapSession* peers, size_t count, uint32_t peer_id,
                                  uint8_t* fingerprint, uint16_t fingerprint_len,
                                  uint8_t* wrapping_key)
{
    PeerWrapSession* slot = NULL;
    for (size_t i = 0; i < count; i++)
    {
        if (peers[i].used && peers[i].peer_id == peer_id)
        {
            if (peers[i].fingerprint_len != fingerprint_len ||
                memcmp(peers[i].fingerprint, fingerprint, fingerprint_len) != 0)
            {
                fprintf(stderr, "[E2E] fingerprint changed for peer #%" PRIu32 "\n", peer_id);
                return -1;
            }
            slot = &peers[i];
            break;
        }
    }

    if (!slot)
    {
        for (size_t i = 0; i < count; i++)
        {
            if (!peers[i].used)
            {
                slot = &peers[i];
            }
        }
    }
    if (!slot)
    {
        fprintf(stderr, "peer wrap table is full\n");
        return -1;
    }

    OPENSSL_cleanse(slot, sizeof(*slot));

    slot->peer_id = peer_id;
    if (fingerprint_len > sizeof(peers[0].fingerprint))
    {
        fprintf(stderr, "fingerprint too long\n");
        return -1;
    }
    memcpy(slot->fingerprint, fingerprint, fingerprint_len);
    slot->fingerprint_len = fingerprint_len;
    memcpy(slot->wrapping_key, wrapping_key, WRAPPING_KEY_LEN);
    slot->used = 1;

    return 0;
}

static void clear_generated_keys(GeneratedKeys* gk)
{
    if (!gk)
    {
        return;
    }
    EVP_PKEY_free(gk->identity_private);
    EVP_PKEY_free(gk->vko_private);
    memset(gk, 0, sizeof(*gk));
}

static int handle_kb(int epfd, uint8_t* data, uint16_t data_len, KeyBundle* my_kb,
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

    if (c->state == STATE_READY && user_entry_exists(ue, kb->client_id) && am_room_leader(c, ue))
    {
        RoomSession* room = get_room_session(rooms, rooms_count, c->room_id);

        if (room)
        {
            if (send_room_key_to_peer(c, kb->client_id, wrapping_key, room) < 0)
            {
                fprintf(stderr, "send_room_key_to_peer failed\n");
                goto cleanup;
            }

            if (set_epollout_to_client(epfd, c) < 0)
            {
                fprintf(stderr, "set_epollout_to_client failed\n");
                goto cleanup;
            }

            printf("[E2E] leader sent room key to peer#%" PRIu32 ", epoch=%" PRIu64 "\n",
                   kb->client_id, room->epoch);
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

typedef enum
{
    ROOM_KEY_ERROR    = -1,
    ROOM_KEY_IGNORED  = 0,
    ROOM_KEY_ACCEPTED = 1
} RoomKeyResult;

// [4 to_client_id]
// [8 epoch]
// [16 nonce]
// [16 tag]
// [32 encrypted_room_key]
// 1. распарсить payload
// 2. проверить to_client_id == c->id
// 3. найти PeerWrapSession по h.sender_id
// 4. вывести enc_key/mac_key через тот же get_kdf
// 5. собрать тот же aad
// 6. проверить tag
// 7. расшифровать encrypted_room_key
// 8. сохранить RoomSession
static int handle_room_key(Client* c, PeerWrapSession* peers, RoomSession* rooms, Header* h,
                           uint8_t* msg, uint16_t msg_len)
{
    if (!c || !peers || !rooms || !h || !msg || msg_len != PKT_ENC_ROOM_KEY_PAYLOAD_LEN)
    {
        return ROOM_KEY_ERROR;
    }
    if (h->room_id != c->room_id)
    {
        return ROOM_KEY_IGNORED;
    }

    uint8_t mac_key[32];
    memset(mac_key, 0, sizeof(mac_key));
    uint8_t enc_key[32];
    memset(enc_key, 0, sizeof(enc_key));
    uint8_t* decrypted_room_key = NULL;
    uint8_t  aad[AAD_LEN];
    memset(aad, 0, sizeof(aad));
    uint16_t decrypted_room_key_len = 0;

    int      ret          = -1;
    uint8_t* p            = msg;
    size_t   off          = 0;
    uint32_t to_client_id = get_u32_be(p + off);
    off += sizeof(to_client_id);

    if (to_client_id != c->id)
    {
        return ROOM_KEY_IGNORED;
    }

    uint64_t epoch = get_u64_be(p + off);
    off += sizeof(epoch);

    uint8_t* nonce = p + off;
    off += PKT_ENC_ROOM_KEY_NONCE_LEN;

    uint8_t* tag = p + off;
    off += PKT_ENC_ROOM_KEY_TAG_LEN;

    uint8_t* ciphertext = p + off;
    off += PKT_ENC_ROOM_KEY_CIPHERTEXT_LEN;

    if (off != msg_len)
    {
        fprintf(stderr, "msg_len mismatch   \n");
        goto cleanup;
    }

    PeerWrapSession* peer = find_peer_wrap_session(peers, MAX_CLIENTS, h->sender_id);
    if (!peer)
    {
        fprintf(stderr, "find_peer_wrap_session failed\n");
        goto cleanup;
    }

    if (build_aad(aad, h->sender_id, to_client_id, h->room_id, epoch) < 0)
    {
        fprintf(stderr, "build_aad failed\n");
        goto cleanup;
    }
    const unsigned char salt_enc[] = "room-key-wrap enc";
    if (get_kdf(peer->wrapping_key, WRAPPING_KEY_LEN, salt_enc, (uint16_t)(sizeof(salt_enc) - 1),
                aad, AAD_LEN, enc_key, 32) < 0)
    {
        fprintf(stderr, "get_kdf failed\n");
        goto cleanup;
    }
    const unsigned char salt_mac[] = "room-key-wrap mac";
    if (get_kdf(peer->wrapping_key, WRAPPING_KEY_LEN, salt_mac, (uint16_t)(sizeof(salt_mac) - 1),
                aad, AAD_LEN, mac_key, 32) < 0)
    {
        fprintf(stderr, "get_kdf failed\n");
        goto cleanup;
    }

    if (kuznechik_decrypt_room_key(nonce, enc_key, ciphertext, PKT_ENC_ROOM_KEY_CIPHERTEXT_LEN,
                                   mac_key, aad, &decrypted_room_key, &decrypted_room_key_len, tag,
                                   PKT_ENC_ROOM_KEY_TAG_LEN) < 0 ||
        !decrypted_room_key)
    {
        fprintf(stderr, "kuznechik_decrypt_room_key failed\n");
        goto cleanup;
    }
    if (decrypted_room_key_len != ROOM_KEY_LEN)
    {
        fprintf(stderr, "kuznechik_decrypt_room_key failed\n");
        goto cleanup;
    }
    RoomSession* old_room = get_room_session(rooms, MAX_ROOMS, h->room_id);

    if (old_room && old_room->epoch == epoch)
    {
        if (memcmp(old_room->room_key, decrypted_room_key, ROOM_KEY_LEN) == 0)
        {

            // дубль уже принятого room key.
            // не ошибка и не новый ключ.

            ret = ROOM_KEY_IGNORED;
            goto cleanup;
        }

        fprintf(stderr, "same epoch but different room key\n");
        goto cleanup;
    }
    if (save_room_session(rooms, MAX_ROOMS, h->room_id, epoch, decrypted_room_key) < 0)
    {
        fprintf(stderr, "save_room_session failed\n");
        goto cleanup;
    }
    printf("[E2E] Got room key for room #%" PRIu32 ", epoch=%" PRIu64 ", from peer#%" PRIu32 "\n",
           h->room_id, epoch, h->sender_id);
    ret = ROOM_KEY_ACCEPTED;
cleanup:
    OPENSSL_clear_free(decrypted_room_key, ROOM_KEY_LEN);
    OPENSSL_cleanse(aad, AAD_LEN);
    OPENSSL_cleanse(mac_key, 32);
    OPENSSL_cleanse(enc_key, 32);

    return ret;
}

static int send_name_command(int epfd, Client* c, uint8_t pkt_type, const char* user_name)
{
    size_t name_len = strlen(user_name);

    if (name_len == 0)
    {
        printf("[ERROR] EMPTY NAME\n");
        return 0;
    }

    if (name_len > MAX_NAME_LEN)
    {
        printf("[ERROR] NAME IS TOO LONG\n");
        return 0;
    }

    Header h;
    memset(&h, 0, sizeof(h));

    h.version    = 1;
    h.flags      = 0;
    h.sender_id  = 0;
    h.room_id    = 0;
    h.timestamp  = 0;
    h.message_id = 0;
    h.type       = pkt_type;

    if (enqueue_packet(c, &h, (const uint8_t*)user_name, name_len) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        return -1;
    }

    if (set_epollout_to_client(epfd, c) < 0)
    {
        return -1;
    }

    memset(c->name, 0, sizeof(c->name));
    memcpy(c->name, user_name, name_len);
    c->name[name_len] = '\0';

    if (pkt_type == PKT_REGISTER_BEGIN)
    {
        c->state = STATE_WAIT_REGISTER_CHALLENGE;
    }
    else if (pkt_type == PKT_NAME)
    {
        c->state = STATE_WAIT_AUTH_CHALLENGE;
    }

    return 0;
}
static void print_help(Client* c)
{
    if (!c || c->state != STATE_READY)
    {
        printf("Commands before login:\n");
        printf("  /help\n");
        printf("  /register NAME\n");
        printf("  /login NAME\n");
        printf("\n");
        printf("You are not in chat yet. Plain text will not be sent.\n");
        return;
    }

    printf("Commands:\n");
    printf("  /help\n");
    printf("  /join ROOM_ID\n");
    printf("\n");
    printf("Plain text is sent to the current room.\n");
}

static int load_keys_for_name(GeneratedKeys* gk, const char* user_name)
{
    EVP_PKEY* identity_private = NULL;
    EVP_PKEY* vko_private      = NULL;

    if (!gk || !user_name)
    {
        return -1;
    }

    clear_generated_keys(gk);

    if (read_private_keys(&identity_private, &vko_private, user_name) < 0 || !identity_private ||
        !vko_private)
    {
        EVP_PKEY_free(identity_private);
        EVP_PKEY_free(vko_private);
        return -1;
    }

    gk->identity_private = identity_private;
    gk->vko_private      = vko_private;

    return 0;
}

// static void remove_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id)
// {
//     for (size_t i = 0; i < rooms_count; i++)
//     {
//         if (rooms[i].used && rooms[i].room_id == room_id)
//         {
//             OPENSSL_cleanse(&rooms[i], sizeof(rooms[i]));
//             return;
//         }
//     }
// }

// 0 некритичная ошибка, клиент может продолжат работу
// -1 критичная ошибка, закрыть клиент
static int handle_input(int epfd, Client* c, RoomSession* rooms, GeneratedKeys* gk, char* out_buf,
                        ssize_t bytes, const char* default_name, int* registration_in_progress,
                        int* generated_keys_for_registration)
{
    Header h;
    memset(&h, 0, sizeof(h));

    h.version    = 1;
    h.flags      = 0;
    h.sender_id  = 0;
    h.room_id    = 0;
    h.timestamp  = 0;
    h.message_id = 0;

    if (bytes == 0)
    {
        return 0;
    }
    if (strcmp(out_buf, "/help") == 0)
    {
        print_help(c);
        return 0;
    }

    if (c->state == STATE_WAIT_NAME)
    {
        if (strncmp(out_buf, "/register ", 10) == 0)
        {
            const char* reg_name = out_buf + 10;

            if (reg_name[0] == '\0')
            {
                printf("[ERROR] Usage: /register NAME\n");
                return 0;
            }

            if (strlen(reg_name) > MAX_NAME_LEN)
            {
                printf("[ERROR] NAME IS TOO LONG\n");
                return 0;
            }

            clear_generated_keys(gk);

            if (keys_exist(reg_name) == 1)
            {
                if (load_keys_for_name(gk, reg_name) < 0)
                {
                    printf("[ERROR] Failed to load local keys for '%s'\n", reg_name);
                    return 0;
                }

                *generated_keys_for_registration = 0;
            }
            else
            {
                gk->identity_private = NULL;
                gk->vko_private      = NULL;

                *generated_keys_for_registration = 0;
            }

            *registration_in_progress = 1;

            return send_name_command(epfd, c, PKT_REGISTER_BEGIN, reg_name);
        }

        if (strcmp(out_buf, "/register") == 0)
        {
            if (strlen(default_name) > MAX_NAME_LEN)
            {
                printf("[ERROR] NAME IS TOO LONG\n");
                return 0;
            }

            clear_generated_keys(gk);

            if (keys_exist(default_name) == 1)
            {
                if (load_keys_for_name(gk, default_name) < 0)
                {
                    printf("[ERROR] Failed to load local keys for '%s'\n", default_name);
                    return 0;
                }

                *generated_keys_for_registration = 0;
            }

            *registration_in_progress = 1;

            return send_name_command(epfd, c, PKT_REGISTER_BEGIN, default_name);
        }

        if (strncmp(out_buf, "/login ", 7) == 0)
        {
            const char* login_name = out_buf + 7;

            if (login_name[0] == '\0')
            {
                printf("[ERROR] Usage: /login NAME\n");
                return 0;
            }

            if (strlen(login_name) > MAX_NAME_LEN)
            {
                printf("[ERROR] NAME IS TOO LONG\n");
                return 0;
            }

            if (keys_exist(login_name) != 1)
            {
                printf("[ERROR] No local keys for '%s'. Use /register %s first.\n", login_name,
                       login_name);
                return 0;
            }

            if (load_keys_for_name(gk, login_name) < 0)
            {
                printf("[ERROR] Failed to load local keys for '%s'\n", login_name);
                return 0;
            }

            *registration_in_progress        = 0;
            *generated_keys_for_registration = 0;

            return send_name_command(epfd, c, PKT_NAME, login_name);
        }

        if (strcmp(out_buf, "/login") == 0)
        {
            if (keys_exist(default_name) != 1)
            {
                printf("[ERROR] No local keys for '%s'. Use /register %s first.\n", default_name,
                       default_name);
                return 0;
            }

            if (load_keys_for_name(gk, default_name) < 0)
            {
                printf("[ERROR] Failed to load local keys for '%s'\n", default_name);
                return 0;
            }

            *registration_in_progress        = 0;
            *generated_keys_for_registration = 0;

            return send_name_command(epfd, c, PKT_NAME, default_name);
        }

        if (out_buf[0] == '/')
        {
            printf("[ERROR] Unknown command: %s\n", out_buf);
            printf("[LOCAL] Type /help to see supported commands.\n");
            return 0;
        }

        printf("[LOCAL] Message was not sent. You are not logged in.\n");
        printf("[LOCAL] Use '/login NAME' or '/register NAME'.\n");
        printf("[LOCAL] Use '/login' or '/register' to use your %s.\n", default_name);
        return 0;
    }

    if (c->state != STATE_READY)
    {
        if (out_buf[0] == '/')
        {
            printf("[LOCAL] Command cannot be used right now. Waiting for server response.\n");
        }
        else
        {
            printf("[LOCAL] Message was not sent. You are not ready yet.\n");
        }

        return 0;
    }

    if (c->state == STATE_READY)
    {
        if (bytes == 0)
        {
            return 0;
        }
        if (bytes > PAYLOAD_SIZE)
        {
            printf("[ERROR] MESSAGE TOO LONG\n");
            return 0;
        }
        if (strncmp("/join ", out_buf, 6) == 0)
        {
            errno = 0;
            char*         end;
            unsigned long room = strtoul(out_buf + 6, &end, 0);
            if (*end != '\0')
            {
                printf("[ERROR] INVALID ROOM ID\n");
                return 0;
            }
            if (end == out_buf + 6)
            {
                printf("[ERROR] ROOM ID IS NOT A NUMBER\n");
                return 0;
            }
            if (errno == ERANGE)
            {
                printf("[ERROR] ROOM ID IS OUT OF RANGE\n");
                return 0;
            }
            if (room == 0 || room > MAX_ROOMS)
            {
                printf("[ERROR] INVALID ROOM ID\n");
                return 0;
            }

            if ((uint32_t)room == c->room_id)
            {
                printf("[LOCAL] You are already in room #%" PRIu32 "\n", c->room_id);
                return 0;
            }
            h.type    = PKT_ROOM_CHANGE;
            h.room_id = (uint32_t)room;

            if (enqueue_packet(c, &h, NULL, 0) < 0)
            {
                fprintf(stderr, "enqueue_packet failed\n");
                return -1;
            }
            if (set_epollout_to_client(epfd, c) < 0)
            {
                return -1;
            }
        }

        else
        {
            h.type            = PKT_ENC_CHAT;
            h.room_id         = c->room_id;
            RoomSession* room = find_room_session(rooms, MAX_ROOMS, c->room_id);
            if (!room)
            {
                fprintf(stderr, "[E2E] no room key for room#%" PRIu32 "\n", c->room_id);
                return 0;
            }
            if (bytes < 0 || bytes > UINT16_MAX)
            {
                fprintf(stderr, "message is too large\n");
                return -1;
            }
            if (client_send_pkt_enc_chat(epfd, c, room, (uint8_t*)out_buf, (uint16_t)bytes) < 0)
            {
                fprintf(stderr, "enqueue_packet failed\n");
                return -1;
            }
            printf("[room #%" PRIu32 "] %s: %s\n", c->room_id, c->name, out_buf);
            if (set_epollout_to_client(epfd, c) < 0)
            {
                return -1;
            }
        }
    }
    return 0;
}

int main(int argc, char** argv)
{
    char* default_name = "default";

    if (argc >= 2)
    {
        default_name = argv[1];
    }
    else
    {
        printf("ENTER YOUR NAME LIKE './client NAME'\n");
        return -1;
    }

    OSSL_PROVIDER* dflt = NULL;
    OSSL_PROVIDER* gost = NULL;
    if (ossl_init_crypto(&dflt, &gost) < 0)
    {
        fprintf(stderr, "ossl_init_crypto failed\n");
        return -1;
    }

    GeneratedKeys gk;
    memset(&gk, 0, sizeof(gk));
    int registration_in_progress        = 0;
    int generated_keys_for_registration = 0;

    gk.identity_private  = NULL;
    gk.vko_private       = NULL;
    int        ret       = -1;
    int        client_fd = -1;
    int        epfd      = -1;
    Client*    c         = NULL;
    EpollItem* stdin     = NULL;
    signal(SIGPIPE, SIG_IGN);
    KeyBundle*         my_kb = NULL;
    struct epoll_event events[2];
    memset(events, 0, sizeof(events));

    char out[OUT_CAP];
    memset(out, 0, sizeof(out));

    char stdin_line[BUF_SIZE];
    memset(stdin_line, 0, BUF_SIZE);
    size_t stdin_line_len  = 0;
    int    stdin_line_drop = 0;

    UserEntry ue[MAX_CLIENTS];
    memset(&ue, 0, sizeof(UserEntry) * MAX_CLIENTS);

    PeerWrapSession peers[MAX_CLIENTS];
    RoomSession     rooms[MAX_ROOMS];
    memset(peers, 0, sizeof(peers));
    memset(rooms, 0, sizeof(rooms));

    size_t name_len = strlen(default_name);

    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0)
    {
        perror("socket");
        goto cleanup;
    }

    struct sockaddr_in server_sa;
    socklen_t          server_len = sizeof(server_sa);
    memset(&server_sa, 0, server_len);
    int rc = inet_pton(AF_INET, SERVER_ADDRESS, &server_sa.sin_addr);
    if (rc == 0)
    {
        fprintf(stderr, "src does not contain a character string representing  a valid network "
                        "address in the specified address family\n");
        goto cleanup;
    }
    else if (rc < 0)
    {
        perror("inet_pton");
        goto cleanup;
    }

    server_sa.sin_family = AF_INET;
    server_sa.sin_port   = htons(SERVER_PORT);

    if (connect(client_fd, (struct sockaddr*)&server_sa, server_len) < 0)
    {
        perror("connect");
        goto cleanup;
    }

    if (set_nonblocking(client_fd) < 0)
    {
        goto cleanup;
    }
    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0)
    {
        perror("epoll_create1");
        goto cleanup;
    }

    c = malloc(sizeof(Client));
    if (c == NULL)
    {
        perror("Client* c malloc");
        goto cleanup;
    }
    memset(c, 0, sizeof(Client));
    c->ei.fd   = client_fd;
    c->ei.item = CLIENT_ITEM;
    c->state   = STATE_WAIT_NAME;

    struct epoll_event ev;
    ev.data.ptr = c;
    ev.events   = EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, c->ei.fd, &ev) < 0)
    {
        perror("epoll_ctl add client");
        goto cleanup;
    }

    stdin = malloc(sizeof(EpollItem));
    if (stdin == NULL)
    {
        perror("EpollItem* stdin malloc");
        goto cleanup;
    }
    stdin->fd   = STDIN_FILENO;
    stdin->item = STDIN_ITEM;
    ev.data.ptr = stdin;
    ev.events   = EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) < 0)
    {
        perror("epoll_ctl add stdin");
        goto cleanup;
    }

    if (name_len == 0 || name_len > MAX_NAME_LEN)
    {
        fprintf(stderr, "bad name length\n");
        goto cleanup;
    }

    printf("[LOCAL] Not logged in.\n");

    printf("[LOCAL] Type '/help', '/login NAME' or '/register NAME'.\n");
    printf("[LOCAL] Use '/login' or '/register' to use your default name: %s\n", default_name);
    while (1)
    {
        int nfds = epoll_wait(epfd, events, 2, -1);
        if (nfds < 0)
        {
            perror("epoll_wait");
            goto cleanup;
        }
        for (int i = 0; i < nfds; i++)
        {
            uint32_t   cur_evs = events[i].events;
            EpollItem* ei      = (EpollItem*)events[i].data.ptr;

            if (ei->item == STDIN_ITEM && cur_evs & EPOLLIN)
            {
                char    read_buf[256];
                ssize_t bytes = read(ei->fd, read_buf, sizeof(read_buf));
                if (bytes < 0)
                {
                    if (errno == EWOULDBLOCK || errno == EAGAIN)
                    {
                        continue;
                    }

                    perror("stdin read");
                    goto cleanup;
                }
                if (bytes == 0)
                {
                    printf("[INFO] STDIN CLOSED, EXITING CLIENT\n");
                    ret = 0;
                    goto cleanup;
                }
                if (bytes > 0)
                {

                    for (ssize_t j = 0; j < bytes; j++)
                    {
                        char ch = read_buf[j];
                        if (ch == '\n')
                        {
                            if (stdin_line_drop)
                            {
                                if (ch == '\n')
                                {
                                    stdin_line_drop = 0;
                                }
                                else
                                {
                                    continue;
                                }
                            }
                            if (stdin_line_len > 0 && stdin_line[stdin_line_len - 1] == '\r')
                            {
                                stdin_line_len--;
                            }
                            stdin_line[stdin_line_len] = '\0';

                            if (handle_input(epfd, c, rooms, &gk, stdin_line, stdin_line_len,
                                             default_name, &registration_in_progress,
                                             &generated_keys_for_registration) < 0)
                            {
                                goto cleanup;
                            }
                            stdin_line_len = 0;
                            continue;
                        }
                        if (stdin_line_len + 1 >= sizeof(stdin_line))
                        {
                            printf("[ERROR] INPUT LINE TOO LONG\n");
                            stdin_line_len  = 0;
                            stdin_line_drop = 1;
                            continue;
                        }
                        stdin_line[stdin_line_len++] = ch;
                    }
                }
            }

            if ((ei->item == CLIENT_ITEM) && (cur_evs & EPOLLIN))
            {
                Client*  c = (Client*)ei;
                uint8_t  msg[PAYLOAD_SIZE];
                uint32_t msg_len = 0;

                while (1)
                {
                    int rc = recv_into_inbuf(c);
                    if (rc == -1)
                    {
                        ret = 0;
                        goto cleanup;
                    }
                    if (rc == -2)
                    {
                        ret = -1;
                        goto cleanup;
                    }
                    if (rc == 0)
                    {
                        break;
                    }
                }
                while (1)
                {
                    Header h;
                    memset(&h, 0, sizeof(h));
                    int rc = try_pop_packet(c, &h, msg, &msg_len);
                    if (rc < 0)
                    {
                        goto cleanup;
                    }
                    else if (rc == 0)
                    {
                        break;
                    }
                    switch (h.type)
                    {
                        case PKT_JOIN:
                        {
                            if (c->state == STATE_READY || c->state == STATE_WAIT_ROOM_KEY)
                            {
                                char     joined_name[MAX_NAME_LEN + 1];
                                uint32_t joined_id = 0;

                                if (parse_client_id_and_name(msg, msg_len, &joined_id,
                                                             joined_name) < 0)
                                {
                                    continue;
                                }

                                int was_ready_before_join = (c->state == STATE_READY);

                                int was_leader_before_join =
                                    (was_ready_before_join && am_room_leader(c, ue));

                                if (add_user_entry(ue, joined_name, joined_id) < 0)
                                {
                                    continue;
                                }

                                printf("[JOIN] %s#%" PRIu32 "\n", joined_name, joined_id);

                                if (was_leader_before_join)
                                {

                                    if (rekey_current_room(epfd, c, peers, MAX_CLIENTS, rooms,
                                                           MAX_ROOMS, ue) < 0)
                                    {
                                        fprintf(stderr, "rekey_current_room failed\n");
                                        break;
                                    }
                                }
                                else if (was_ready_before_join)
                                {

                                    c->state = STATE_WAIT_ROOM_KEY;

                                    printf(
                                        "[E2E] Waiting for new room key after join in room#%" PRIu32
                                        "\n",
                                        c->room_id);
                                }
                            }

                            break;
                        }
                        case PKT_REGISTER_CHALLENGE:
                        {
                            if (c->state != STATE_WAIT_REGISTER_CHALLENGE)
                            {
                                fprintf(stderr, "unexpected PKT_REGISTER_CHALLENGE\n");
                                break;
                            }

                            if (msg_len != 4 + CHALLENGE_LEN)
                            {
                                fprintf(stderr, "bad register challenge length\n");
                                goto cleanup;
                            }

                            uint32_t       client_id = get_u32_be(msg);
                            const uint8_t* challenge = msg + 4;

                            c->id = client_id;

                            if (!gk.identity_private || !gk.vko_private)
                            {
                                if (generate_keys_in_memory(&gk) < 0)
                                {
                                    fprintf(stderr, "generate_keys_in_memory failed\n");
                                    goto cleanup;
                                }

                                generated_keys_for_registration = 1;
                            }

                            uint8_t* identity_public_der     = NULL;
                            uint16_t identity_public_der_len = 0;

                            if (key_to_der_pub(gk.identity_private, &identity_public_der,
                                               &identity_public_der_len) < 0)
                            {
                                fprintf(stderr, "key_to_der_pub failed\n");
                                goto cleanup;
                            }

                            uint8_t* sig     = NULL;
                            size_t   sig_len = 0;

                            if (get_sign_register_commit(c->id, c->name, challenge,
                                                         gk.identity_private, identity_public_der,
                                                         identity_public_der_len, &sig,
                                                         &sig_len) < 0)
                            {
                                fprintf(stderr, "get_sign_register_commit failed\n");
                                OPENSSL_free(identity_public_der);
                                goto cleanup;
                            }

                            if (sig_len > UINT16_MAX)
                            {
                                fprintf(stderr, "signature too large\n");
                                OPENSSL_free(identity_public_der);
                                OPENSSL_free(sig);
                                goto cleanup;
                            }

                            if (client_send_pkt_register_commit(epfd, c, identity_public_der,
                                                                identity_public_der_len, sig,
                                                                (uint16_t)sig_len) < 0)
                            {
                                fprintf(stderr, "client_send_pkt_register_commit failed\n");
                                OPENSSL_free(identity_public_der);
                                OPENSSL_free(sig);
                                goto cleanup;
                            }

                            OPENSSL_free(identity_public_der);
                            OPENSSL_free(sig);

                            c->state = STATE_WAIT_REGISTER_OK;

                            break;
                        }
                        case PKT_REGISTER_OK:
                        {
                            if (c->state == STATE_WAIT_REGISTER_OK)
                            {
                                char     my_name[MAX_NAME_LEN + 1];
                                uint32_t my_id         = 0;
                                uint32_t start_room_id = 0;
                                if (parse_client_register_ok(msg, msg_len, &my_id, &start_room_id,
                                                             my_name) < 0)
                                {
                                    continue;
                                }
                                c->id              = my_id;
                                c->room_id         = start_room_id;
                                size_t my_name_len = strlen(my_name);
                                memcpy(c->name, my_name, my_name_len);
                                c->name[my_name_len] = '\0';
                                if (registration_in_progress && generated_keys_for_registration)
                                {
                                    if (save_keys_from_memory(c->name, &gk) < 0)
                                    {
                                        fprintf(stderr, "save_keys_from_memory failed\n");
                                        continue;
                                    }

                                    generated_keys_for_registration = 0;
                                }

                                registration_in_progress = 0;

                                KeyBundle* kb = calloc(1, sizeof(*kb));
                                if (!kb)
                                {
                                    ossl_print_error("OPENSSL_zalloc");
                                    continue;
                                }
                                if (init_key_bundle(kb, c->id, gk.identity_private, c->name) < 0 ||
                                    !kb)
                                {
                                    kb_free(kb);
                                    fprintf(stderr, "init_key_bundle failed\n");
                                    continue;
                                }

                                uint8_t* kb_der     = NULL;
                                uint16_t kb_der_len = 0;

                                if (serialize_key_bundle_full(kb, &kb_der, &kb_der_len) < 0 ||
                                    !kb_der || !kb_der_len)
                                {
                                    fprintf(stderr, "serialize_key_bundle_full failed\n");
                                    kb_free(kb);
                                    continue;
                                }
                                my_kb = kb;
                                kb    = NULL;

                                if (send_kb(c, kb_der, kb_der_len, c->id, c->room_id, NULL) < 0)
                                {
                                    fprintf(stderr, "serialize_key_bundle_full failed\n");
                                    kb_free(kb);
                                    OPENSSL_free(kb_der);
                                    continue;
                                }

                                c->state = STATE_WAIT_ROOM_KEY;

                                if (set_epollout_to_client(epfd, c) < 0)
                                {
                                    fprintf(stderr, "set_epollout_to_client failed\n");
                                    kb_free(kb);
                                    OPENSSL_free(kb_der);
                                    continue;
                                }
                                OPENSSL_free(kb_der);
                                kb_free(kb);
                            }
                            break;
                        }
                        case PKT_AUTH_CHALLENGE:
                        {
                            if (c->state != STATE_WAIT_AUTH_CHALLENGE)
                            {
                                break;
                            }
                            if (msg_len != AUTH_CHALLENGE_PAYLOAD_LEN)
                            {
                                break;
                            }
                            uint32_t challenged_id = get_u32_be(msg);
                            c->id                  = challenged_id;
                            if (msg_len > UINT16_MAX)
                            {
                                fprintf(stderr, "payload too large\n");
                                break;
                            }

                            if (client_response_challenge(epfd, c, msg, (uint16_t)msg_len,
                                                          gk.identity_private) < 0)
                            {
                                fprintf(stderr, "client_response_challenge failed\n");
                                break;
                            }
                            c->state = STATE_WAIT_REGISTER_OK;

                            break;
                        }
                        case PKT_ENC_KEY_BUNDLE:
                        {
                            if (msg_len > UINT16_MAX)
                            {
                                fprintf(stderr, "payload too large\n");
                                break;
                            }

                            if (handle_kb(epfd, msg, (uint16_t)msg_len, my_kb, gk.vko_private,
                                          peers, MAX_CLIENTS, rooms, MAX_ROOMS, ue, c) < 0)
                            {
                                fprintf(stderr, "handle_kb failed\n");
                                break;
                            }
                            break;
                        }
                        case PKT_ENC_ROOM_KEY:
                        {
                            if (msg_len > UINT16_MAX)
                            {
                                fprintf(stderr, "payload too large\n");
                                break;
                            }
                            RoomKeyResult r =
                                handle_room_key(c, peers, rooms, &h, msg, (uint16_t)msg_len);

                            if (r == ROOM_KEY_ERROR)
                            {
                                fprintf(stderr, "handle_room_key failed\n");
                                break;
                            }

                            if (r == ROOM_KEY_ACCEPTED)
                            {
                                c->state = STATE_READY;
                            }

                            break;
                        }
                        case PKT_ROOM_SYNC_DONE:
                        {
                            if (!room_has_peers(ue))
                            {
                                if (create_room_key(rooms, MAX_ROOMS, c->room_id) < 0)
                                {
                                    fprintf(stderr, "create_room_key failed\n");
                                    break;
                                }

                                c->state = STATE_READY;
                            }
                            else
                            {
                                c->state = STATE_WAIT_ROOM_KEY;

                                printf("[E2E] Waiting for room key in room#%" PRIu32 "\n",
                                       c->room_id);
                            }

                            break;
                        }
                        case PKT_LEAVE:
                        {
                            uint32_t left_id;
                            char     left_name[MAX_NAME_LEN + 1];

                            if (parse_client_id_and_name(msg, msg_len, &left_id, left_name) < 0)
                            {
                                continue;
                            }

                            if (remove_user_entry_by_id(ue, left_id) < 0)
                            {
                                continue;
                            }

                            printf("[LEAVE] %s#%" PRIu32 "\n", left_name, left_id);

                            if (!room_has_peers(ue))
                            {
                                if (create_room_key(rooms, MAX_ROOMS, c->room_id) < 0)
                                {
                                    fprintf(stderr, "create_room_key failed\n");
                                    break;
                                }

                                c->state = STATE_READY;

                                printf("[E2E] no peers left; created new room key for room#%" PRIu32
                                       "\n",
                                       c->room_id);

                                break;
                            }

                            if (am_room_leader(c, ue))
                            {
                                if (rekey_current_room_as_leader(epfd, c, peers, MAX_CLIENTS, rooms,
                                                                 MAX_ROOMS, ue) < 0)
                                {
                                    fprintf(stderr, "rekey_current_room_as_leader failed\n");
                                    break;
                                }
                            }
                            else
                            {
                                c->state = STATE_WAIT_ROOM_KEY;
                                printf("[E2E] Waiting for new room key after leave in room#%" PRIu32
                                       "\n",
                                       c->room_id);
                            }

                            break;
                        }

                        case PKT_CHAT:
                        {
                            memset(out, 0, sizeof(out));
                            if (payload_to_str(msg, msg_len, out, OUT_CAP) == 0)
                            {
                                const char* name = find_user_name_by_id(ue, h.sender_id);
                                if (name == NULL)
                                {
                                }
                                printf("[room %" PRIu32 "] %s#%" PRIu32 ": %s\n", h.room_id,
                                       name ? name : "NULL", h.sender_id, out);
                            }
                            break;
                        }
                        case PKT_ERR:
                        {
                            memset(out, 0, sizeof(out));

                            if (payload_to_str(msg, msg_len, out, OUT_CAP) == 0)
                            {
                                printf("[ERROR] %s\n", out);

                                if (c->state == STATE_WAIT_AUTH_CHALLENGE ||
                                    c->state == STATE_WAIT_REGISTER_CHALLENGE ||
                                    c->state == STATE_WAIT_REGISTER_OK)
                                {
                                    c->state                 = STATE_WAIT_NAME;
                                    registration_in_progress = 0;

                                    printf("[LOCAL] You are not logged in.\n");
                                    printf("[LOCAL] Type /help, /login %s or /register %s.\n",
                                           c->name, c->name);
                                }
                            }

                            break;
                        }
                        // 1. очистить user list
                        // 2. перейти в STATE_WAIT_ROOM_KEY
                        // 3. не использовать старый room_key для новой комнаты
                        // 4. создать новый ключ, если в комнате никого нет
                        // 5. ждать room key, если кто-то уже есть
                        case PKT_ROOM_CHANGE_OK:
                        {
                            uint32_t prev_room = c->room_id;

                            if (h.room_id == c->room_id)
                            {
                                c->state = STATE_READY;
                                printf("[ROOM CHANGE] You are already in room #%" PRIu32 "\n",
                                       c->room_id);
                                break;
                            }

                            memset(ue, 0, sizeof(UserEntry) * MAX_CLIENTS);

                            c->room_id = h.room_id;
                            c->state   = STATE_WAIT_ROOM_KEY;

                            printf("[ROOM CHANGE] You've changed your room from %" PRIu32
                                   " to %" PRIu32 "\n",
                                   prev_room, c->room_id);

                            break;
                        }
                        case PKT_ENC_CHAT:
                        {
                            if (c->state != STATE_READY)
                            {
                                break;
                            }

                            if (h.room_id != c->room_id)
                            {
                                break;
                            }
                            RoomSession* room = find_room_session(rooms, MAX_ROOMS, c->room_id);
                            if (!room)
                            {
                                fprintf(stderr, "find_room_session failed\n");
                                break;
                            }
                            uint8_t* payload     = NULL;
                            uint16_t payload_len = 0;
                            if (client_recv_pkt_enc_chat(c, &h, room, msg, msg_len, &payload,
                                                         &payload_len) < 0)
                            {
                                fprintf(stderr, "client_recv_pkt_enc_chat failed\n");
                                break;
                            }
                            char out[OUT_CAP];

                            if (payload_to_str(payload, payload_len, out, OUT_CAP) < 0)
                            {
                                fprintf(stderr, "payload_to_str failed\n");
                                OPENSSL_clear_free(payload, payload_len);
                                break;
                            }
                            const char* name = find_user_name_by_id(ue, h.sender_id);
                            printf("[room #%" PRIu32 "] %s: %s\n", h.room_id, name ? name : "NULL",
                                   out);
                            OPENSSL_clear_free(payload, payload_len);
                            break;
                        }

                        default:
                        {
                            const char* p_t = packet_type_str(h.type);
                            printf("[ERROR] UNKNOWN PACKET TYPE: %s\n", p_t);
                            break;
                        }
                    }
                }
            }

            if ((ei->item == CLIENT_ITEM) && cur_evs & EPOLLOUT)
            {
                Client* c  = (Client*)ei;
                int     rc = flush_send(c);
                if (rc < 0)
                {
                    goto cleanup;
                }
                else if (c->conn.out_len == 0)
                {
                    if (unset_epollout_to_client(epfd, c) < 0)
                    {

                        goto cleanup;
                    }
                }
                else if (rc == 0)
                {
                    continue;
                }
            }
            if (cur_evs & EPOLLHUP || cur_evs & EPOLLRDHUP || cur_evs & EPOLLERR)
            {
                if ((cur_evs & EPOLLERR) != 0)
                {
                    ret = -1;
                    goto cleanup;
                }
                if ((cur_evs & EPOLLHUP) != 0 || (cur_evs & EPOLLRDHUP) != 0)
                {
                    ret = 0;
                    goto cleanup;
                }
            }
        }
    }

    ret = 0;
cleanup:
    kb_free(my_kb);
    ossl_destroy_crypto(&dflt, &gost);
    if (client_fd >= 0)
    {
        close(client_fd);
    }
    if (epfd >= 0)
    {
        close(epfd);
    }
    free(stdin);
    free(c);
    return ret;
}
