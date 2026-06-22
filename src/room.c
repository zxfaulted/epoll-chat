#include "room.h"
#include "client_send.h"
#include "crypto.h"
#include "e2e_message.h"
#include "net.h"
#include "room_crypto.h"
#include "transport.h"
#include "types.h"
#include <stdio.h>
#include <string.h>

RoomSession* get_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id)
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

uint64_t get_room_epoch(RoomSession* room)
{
    return room->epoch;
}

int save_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id, uint64_t epoch,
                      uint8_t room_key[ROOM_KEY_LEN])
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
int save_password_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id,
                               uint8_t enc_key[PASSWORD_KEY_LEN], uint8_t mac_key[PASSWORD_KEY_LEN],
                               uint8_t salt[ROOM_SALT_LEN], uint64_t epoch,
                               uint8_t room_key[ROOM_KEY_LEN])
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
    slot->send_seq                = 1;
    slot->used                    = 1;
    slot->has_password            = 1;
    slot->has_passsword_wrap_keys = 1;
    memcpy(slot->enc_key, enc_key, PASSWORD_KEY_LEN);
    memcpy(slot->mac_key, mac_key, PASSWORD_KEY_LEN);
    memcpy(slot->salt, salt, ROOM_SALT_LEN);
    return 0;
}

uint32_t room_leader_id(const Client* c, const UserEntry* ue)
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

int am_room_leader(const Client* c, const UserEntry* ue)
{
    if (!c || !ue || c->id == 0)
    {
        return 0;
    }

    return room_leader_id(c, ue) == c->id;
}

int create_room_key(RoomSession* rooms, size_t count, uint32_t room_id)
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

RoomSession* find_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id)
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

int rekey_current_room(int epfd, Client* c, PeerWrapSession* peers, size_t peers_count,
                       RoomSession* rooms, size_t rooms_count, UserEntry* ue)
{
    if (room_has_peers(ue) && !get_room_session(rooms, rooms_count, c->room_id))
    {
        fprintf(stderr, "[E2E] no old room key; cannot rekey safely\n");
        c->room_state = ROOM_WAIT_ROOM_KEY;
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

    c->room_state = ROOM_READY;
    return 0;
}

int rekey_current_room_as_leader(int epfd, Client* c, PeerWrapSession* peers, size_t peers_count,
                                 RoomSession* rooms, size_t rooms_count, UserEntry* ue)
{
    if (!am_room_leader(c, ue))
    {
        return 0;
    }

    return rekey_current_room(epfd, c, peers, peers_count, rooms, rooms_count, ue);
}

PeerWrapSession* find_peer_wrap_session(PeerWrapSession* peers, size_t count, uint32_t peer_id)
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

int send_room_key_to_known_peers(int epfd, Client* c, PeerWrapSession* peers, size_t peers_count,
                                 RoomSession* rooms, size_t rooms_count, UserEntry* ue)
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

        if (ue[i].id == c->id)
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

// [4 to_client_id]
// [8 epoch]
// [16 nonce]
// [16 tag]
// [32 encrypted_room_key]
int send_room_key_to_peer(Client* c, uint32_t peer_id, uint8_t* wrapping_key, RoomSession* room)
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

int forward_room_key_packet(int epfd, Client* clients[], int clients_count, Client* from, Header* h,
                            uint8_t* msg, uint32_t msg_len, uint32_t* message_id)
{
    if (!clients || !from || !h || !msg || !message_id)
    {
        return -1;
    }

    if (msg_len != PKT_ENC_ROOM_KEY_PAYLOAD_LEN)
    {
        send_server_error(epfd, from, "WRONG PAYLOAD LEN", message_id);
        return -1;
    }

    if (h->room_id != from->room_id)
    {
        send_server_error(epfd, from, "YOU ARE NOT IN THIS ROOM", message_id);
        return 0;
    }

    uint32_t to_client_id = get_u32_be(msg);

    if (to_client_id == from->id)
    {
        send_server_error(epfd, from, "YOU ARE NOT IN THIS ROOM", message_id);
        return 0;
    }

    Client* to = find_client(clients, clients_count, to_client_id);
    if (!to)
    {
        send_server_error(epfd, from, "NO CLIENT WITH THAT ID", message_id);
        return 0;
    }

    if (to->room_id != from->room_id)
    {
        send_server_error(epfd, from, "YOU ARE NOT IN DIFFERENT ROOMS", message_id);
        return 0;
    }

    Header h_out     = {0};
    h_out.flags      = 0;
    h_out.message_id = next_message_id(message_id);
    h_out.room_id    = from->room_id;
    h_out.sender_id  = from->id;
    h_out.timestamp  = (uint64_t)time(NULL);
    h_out.type       = PKT_ENC_ROOM_KEY;
    h_out.version    = 1;

    if (enqueue_packet(to, &h_out, msg, msg_len) < 0)
    {
        return -1;
    }

    if (set_epollout_to_client(epfd, to) < 0)
    {
        return -1;
    }
    return 0;
}

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
int handle_room_key(Client* c, PeerWrapSession* peers, RoomSession* rooms, Header* h, uint8_t* msg,
                    uint16_t msg_len)
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
                                   mac_key, aad, sizeof(aad), &decrypted_room_key,
                                   &decrypted_room_key_len, tag, PKT_ENC_ROOM_KEY_TAG_LEN) < 0 ||
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
    else if (old_room && old_room->epoch > epoch)
    {
        fprintf(stderr, "old epoch\n");
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

// [1  enc_version]
// [1  suite]
// [2  reserved]
// [8  room_epoch]
// [8  seq]
// [16 nonce]
// [N  ciphertext]
// [16 tag]
int check_recv_seq(RoomSession* room, uint64_t peer_id, uint64_t recv_seq)
{
    RoomPeerRecvState* slot = NULL;
    for (size_t i = 0; i < MAX_CLIENTS; i++)
    {
        if (room->recv[i].used && room->recv[i].peer_id == peer_id)
        {
            slot = &room->recv[i];
            break;
        }
    }
    if (!slot)
    {
        for (size_t i = 0; i < MAX_CLIENTS; i++)
        {
            if (!room->recv[i].used)
            {
                slot          = &room->recv[i];
                slot->peer_id = peer_id;
                slot->seq     = 0;
                slot->used    = 1;
                break;
            }
        }
    }
    if (!slot)
    {
        fprintf(stderr, "recv table is full\n");
        return -1;
    }

    if (slot->seq >= recv_seq)
    {
        fprintf(stderr, "replay detected for peer#%" PRIu64 "\n", peer_id);
        return -1;
    }
    slot->seq = recv_seq;
    return 0;
}

int rekey_current_password_room(int epfd, Client* c, PeerWrapSession* peers, uint16_t peers_count,
                                RoomSession* rooms, uint16_t rooms_count, UserEntry* ue,
                                uint32_t room_id)
{
    RoomSession* room = find_room_session(rooms, rooms_count, room_id);
    if (!room)
    {
        return -1;
    }

    uint64_t new_epoch = room->epoch + 1;

    uint8_t new_room_key[ROOM_KEY_LEN];
    memset(new_room_key, 0, ROOM_KEY_LEN);
    if (RAND_bytes(new_room_key, ROOM_KEY_LEN) != 1)
    {
        ossl_print_error("RAND_bytes");
        return -1;
    }

    RoomPasswordInfo rpi;
    memset(&rpi, 0, sizeof(rpi));
    memcpy(rpi.salt, room->salt, ROOM_SALT_LEN);

    uint8_t nonce[ROOM_NONCE_LEN];
    memset(nonce, 0, ROOM_NONCE_LEN);
    if (RAND_bytes(nonce, ROOM_NONCE_LEN) != 1)
    {
        ossl_print_error("RAND_bytes");
        return -1;
    }
    memcpy(&rpi.salt, room->salt, ROOM_SALT_LEN);
    memcpy(&rpi.nonce, nonce, ROOM_NONCE_LEN);
    rpi.epoch = new_epoch;

    if (encrypt_room_key_with_password_keys(room_id, room->enc_key, room->mac_key, new_room_key,
                                            &rpi) < 0)
    {
        fprintf(stderr, "encrypt_room_key_with_password_keys\n");
        return -1;
    }

    if (get_verifier(room->mac_key, room_id, rpi.epoch, rpi.verifier) < 0)
    {
        fprintf(stderr, "get_verifier failed\n");
        OPENSSL_cleanse(new_room_key, ROOM_KEY_LEN);
        return -1;
    }

    if (save_password_room_session(rooms, rooms_count, room_id, room->enc_key, room->mac_key,
                                   room->salt, new_epoch, new_room_key) < 0)
    {
        return -1;
    }
    if (client_send_password_room_rekey(epfd, c, &rpi) < 0)
    {
        return -1;
    }

    if (send_room_key_to_known_peers(epfd, c, peers, peers_count, rooms, rooms_count, ue) < 0)
    {
        fprintf(stderr, "send_room_key_to_known_peers failed\n");
        return -1;
    }

    c->room_state = ROOM_READY;
    OPENSSL_cleanse(new_room_key, ROOM_KEY_LEN);
    return 0;
}

int rekey_current_room_auto(int epfd, Client* c, PeerWrapSession* peers, uint16_t peers_count,
                            RoomSession* rooms, uint16_t rooms_count, UserEntry* ue,
                            uint32_t room_id)
{
    RoomSession* room = find_room_session(rooms, rooms_count, room_id);
    if (!room)
    {
        return -1;
    }

    if (room->has_password)
    {
        return rekey_current_password_room(epfd, c, peers, peers_count, rooms, rooms_count, ue,
                                           room_id);
    }

    return rekey_current_room(epfd, c, peers, peers_count, rooms, rooms_count, ue);
}