#include "auth/auth.h"
#include "auth/key_bundle.h"
#include "client/client_commands.h"
#include "client/client_recv.h"
#include "client/client_send.h"
#include "common/types.h"
#include "crypto/crypto.h"
#include "crypto/crypto_core.h"
#include "e2e/client_room_session.h"
#include "e2e/room_crypto.h"
#include "protocol/packet_parse.h"
#include "protocol/protocol_debug.h"
#include "storage/der_io.h"
#include "transport/epoll_io.h"
#include "transport/packet_io.h"
#include "transport/tcp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define OUT_CAP (PAYLOAD_SIZE + 1)

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
    c->ei.fd      = client_fd;
    c->ei.item    = CLIENT_ITEM;
    c->auth_state = AUTH_NEW;

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
                            if (c->auth_state == AUTH_READY &&
                                (c->room_state == ROOM_READY || c->room_state == ROOM_SYNCING ||
                                 c->room_state == ROOM_WAIT_ROOM_KEY))
                            {
                                char     joined_name[MAX_NAME_LEN + 1];
                                uint32_t joined_id = 0;

                                if (packet_parse_client_id_name(msg, msg_len, &joined_id,
                                                                joined_name) < 0)
                                {
                                    continue;
                                }

                                int was_ready_before_join = (c->room_state == ROOM_READY);

                                int was_leader_before_join =
                                    (was_ready_before_join && am_room_leader(c, ue));

                                if (add_user_entry(ue, joined_name, joined_id) < 0)
                                {
                                    continue;
                                }

                                printf("[JOIN] %s#%" PRIu32 "\n", joined_name, joined_id);

                                if (was_leader_before_join)
                                {
                                    PeerWrapSession* peer =
                                        find_peer_wrap_session(peers, MAX_CLIENTS, joined_id);
                                    if (!peer)
                                    {
                                        fprintf(stderr,
                                                "[E2E] NO PEER SESSION FOR JOINED CLIENT\n");
                                        break;
                                    }
                                    RoomSession* room =
                                        find_room_session(rooms, MAX_ROOMS, c->room_id);
                                    if (send_room_key_to_peer(epfd, c, joined_id,
                                                              peer->wrapping_key, room) < 0)
                                    {
                                        fprintf(stderr,
                                                "[E2E] FAILED TO SEND OLD ROOM KEY TO PEEY\n");
                                        break;
                                    }
                                    printf("[E2E] Sent old room key to joined #%" PRIu32 "\n",
                                           joined_id);
                                    if (!am_room_leader(c, ue))
                                    {
                                        c->room_state = ROOM_WAIT_ROOM_KEY;

                                        printf("[E2E] Waiting for new room key after join in "
                                               "room#%" PRIu32 "\n",
                                               c->room_id);
                                    }
                                    if (set_epollout_to_client(epfd, c) < 0)
                                    {
                                        fprintf(stderr, "set_epollout_to_client failed\n");
                                        break;
                                    }
                                }
                                else if (was_ready_before_join)
                                {

                                    c->room_state = ROOM_WAIT_ROOM_KEY;

                                    printf(
                                        "[E2E] Waiting for new room key after join in room#%" PRIu32
                                        "\n",
                                        c->room_id);
                                }
                            }

                            break;
                        }
                        case PKT_ROOM_PASSWORD_INFO:
                        {
                            if (c->room_state != ROOM_JOINING)
                            {
                                fprintf(stderr, "UNEXPECTED PKT_ROOM_PASSWORD_INFO\n");
                                break;
                            }
                            c->room_state = ROOM_PASSWORD_UNLOCKING;

                            uint32_t         room_id;
                            RoomPasswordInfo rpi;
                            if (client_recv_pkt_room_password_info(msg, msg_len, &room_id, &rpi) <
                                0)
                            {
                                fprintf(stderr,
                                        "[ERROR] client_recv_pkt_room_password_info failed");
                                break;
                            }

                            printf("[PASSWORD] Please enter password (or 'exit') for room %" PRIu32
                                   ": ",
                                   room_id);
                            int      try_ret            = -99;
                            char     password[128]      = {0};
                            uint8_t* decrypted_room_key = OPENSSL_malloc(ROOM_KEY_LEN);
                            if (!decrypted_room_key)
                            {
                                ossl_print_error("OPENSSL_malloc");
                                return -1;
                            }
                            int     unlocked = 0;
                            uint8_t verifier[ROOM_PASSWORD_VERIFIER_LEN];
                            while (try_ret != 0)
                            {
                                scanf("%127s", password);
                                if (strncmp(password, "exit", 4) == 0)
                                {
                                    break;
                                }
                                uint8_t enc_key[PASSWORD_KEY_LEN];
                                uint8_t mac_key[PASSWORD_KEY_LEN];
                                memset(enc_key, 0, PASSWORD_KEY_LEN);
                                memset(mac_key, 0, PASSWORD_KEY_LEN);
                                try_ret = try_decrypt_room_key_ex(
                                    room_id, (uint8_t*)password, (uint16_t)strlen(password), &rpi,
                                    decrypted_room_key, enc_key, mac_key);
                                if (try_ret == -1)
                                {
                                    fprintf(stderr,
                                            "[ERROR] try_decrypt_room_key failed. Aborting.");
                                    break;
                                }
                                else if (try_ret == -2)
                                {
                                    printf("[ERROR] Wrong password. Please, try again: ");
                                }
                                else
                                {
                                    if (save_password_room_session(
                                            rooms, MAX_ROOMS, room_id, enc_key, mac_key, rpi.salt,
                                            rpi.epoch, decrypted_room_key) < 0)
                                    {
                                        fprintf(stderr, "[ERROR] save_room_session failed\n");
                                        break;
                                    }

                                    if (get_verifier(mac_key, room_id, rpi.epoch, verifier) < 0)
                                    {
                                        fprintf(stderr, "[ERROR] get_verifier failed\n");
                                        break;
                                    }

                                    OPENSSL_cleanse(password, MAX_PASSWORD_LEN);
                                    OPENSSL_cleanse(decrypted_room_key, ROOM_KEY_LEN);
                                    OPENSSL_cleanse(enc_key, PASSWORD_KEY_LEN);
                                    OPENSSL_cleanse(mac_key, PASSWORD_KEY_LEN);
                                    OPENSSL_clear_free(decrypted_room_key, ROOM_KEY_LEN);
                                    unlocked = 1;
                                    break;
                                }
                            }
                            if (unlocked)
                            {
                                if (client_send_pkt_room_unlock(epfd, c, room_id, rpi.epoch,
                                                                verifier) < 0)
                                {
                                    fprintf(stderr, "client_send_pkt_room_unlock failed\n");
                                    return -1;
                                }
                                c->room_state = ROOM_WAIT_JOIN_OK;
                            }
                            break;
                        }
                        case PKT_REGISTER_CHALLENGE:
                        {
                            if (c->auth_state != AUTH_CLIENT_WAIT_REGISTER_CHALLENGE)
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

                            if (client_send_register_commit(epfd, c, identity_public_der,
                                                            identity_public_der_len, sig,
                                                            (uint16_t)sig_len) < 0)
                            {
                                fprintf(stderr, "client_send_register_commit failed\n");
                                OPENSSL_free(identity_public_der);
                                OPENSSL_free(sig);
                                goto cleanup;
                            }

                            OPENSSL_free(identity_public_der);
                            OPENSSL_free(sig);

                            c->auth_state = AUTH_CLIENT_WAIT_REGISTER_OK;

                            break;
                        }
                        case PKT_REGISTER_OK:
                        case PKT_AUTH_OK:
                        {
                            if (c->auth_state == AUTH_CLIENT_WAIT_REGISTER_OK ||
                                c->auth_state == AUTH_CLIENT_WAIT_AUTH_OK)
                            {

                                char     my_name[MAX_NAME_LEN + 1];
                                uint32_t my_id      = 0;
                                uint32_t my_room_id = 0;
                                if (packet_parse_auth_register_ok(msg, msg_len, &my_id, &my_room_id,
                                                                  my_name) < 0)
                                {
                                    continue;
                                }
                                c->id              = my_id;
                                c->room_id         = my_room_id;
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

                                c->auth_state = AUTH_READY;

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

                                c->room_state = ROOM_SYNCING;

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
                        case PKT_ROOM_CREATE_OK:
                        {
                            printf("[ROOM CREATE] Created room #%" PRIu32 ". Use /join %" PRIu32
                                   " to enter\n",
                                   h.room_id, h.room_id);
                            break;
                        }
                        case PKT_AUTH_CHALLENGE:
                        {
                            if (c->auth_state != AUTH_CLIENT_WAIT_AUTH_CHALLENGE)
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

                            if (client_send_challenge_response(epfd, c, msg, (uint16_t)msg_len,
                                                               gk.identity_private) < 0)
                            {
                                fprintf(stderr, "client_send_challenge_response failed\n");
                                break;
                            }
                            c->auth_state = AUTH_CLIENT_WAIT_AUTH_OK;

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
                                c->room_state = ROOM_READY;
                                if (room_has_peers(ue) && am_room_leader(c, ue))
                                {
                                    if (rekey_current_room_auto(epfd, c, peers, MAX_CLIENTS, rooms,
                                                                MAX_ROOMS, ue, c->room_id) < 0)
                                    {
                                        fprintf(stderr, "rekey_current_room_auto failed\n");
                                        break;
                                    }
                                }
                            }

                            break;
                        }
                        case PKT_ROOM_SYNC_DONE:
                        {
                            RoomSession* room = find_room_session(rooms, MAX_ROOMS, c->room_id);
                            // ключ уже был получен до sync через пароль
                            if (room)
                            {
                                c->room_state = ROOM_READY;
                                break;
                            }
                            if (!room_has_peers(ue))
                            {
                                if (create_room_key(rooms, MAX_ROOMS, c->room_id) < 0)
                                {
                                    fprintf(stderr, "create_room_key failed\n");
                                    break;
                                }
                                printf("[E2E] Room is empty. Created new room key\n");
                                c->room_state = ROOM_READY;
                            }
                            else
                            {
                                c->room_state = ROOM_WAIT_ROOM_KEY;
                                printf("[E2E] Waiting for room key in room#%" PRIu32 "\n",
                                       c->room_id);
                            }

                            break;
                        }
                        case PKT_LEAVE:
                        {
                            uint32_t left_id;
                            char     left_name[MAX_NAME_LEN + 1];

                            if (packet_parse_client_id_name(msg, msg_len, &left_id, left_name) < 0)
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

                                c->room_state = ROOM_READY;

                                printf("[E2E] no peers left; created new room key for room#%" PRIu32
                                       "\n",
                                       c->room_id);

                                break;
                            }

                            if (am_room_leader(c, ue))
                            {
                                if (rekey_current_room_auto(epfd, c, peers, MAX_CLIENTS, rooms,
                                                            MAX_ROOMS, ue, c->room_id) < 0)
                                {
                                    fprintf(stderr, "rekey_current_room_auto failed\n");
                                    break;
                                }
                            }
                            else
                            {
                                c->room_state = ROOM_WAIT_ROOM_KEY;
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

                                if (c->auth_state == AUTH_CLIENT_WAIT_AUTH_CHALLENGE ||
                                    c->auth_state == AUTH_CLIENT_WAIT_REGISTER_CHALLENGE ||
                                    c->auth_state == AUTH_CLIENT_WAIT_REGISTER_OK)
                                {
                                    c->auth_state            = AUTH_NEW;
                                    registration_in_progress = 0;

                                    printf("[LOCAL] You are not logged in.\n");
                                    printf("[LOCAL] Type /help, /login %s or /register %s.\n",
                                           c->name, c->name);
                                }
                            }

                            break;
                        }
                        // 1. очистить user list
                        // 2. перейти в C_WAIT_ROOM_KEY
                        // 3. не использовать старый room_key для новой комнаты
                        // 4. создать новый ключ, если в комнате никого нет
                        // 5. ждать room key, если кто-то уже есть
                        case PKT_ROOM_CHANGE_OK:
                        {
                            uint32_t prev_room = c->room_id;

                            if (h.room_id == c->room_id)
                            {
                                c->room_state = ROOM_READY;
                                printf("[ROOM CHANGE] You are already in room #%" PRIu32 "\n",
                                       c->room_id);
                                break;
                            }

                            memset(ue, 0, sizeof(UserEntry) * MAX_CLIENTS);

                            c->room_id    = h.room_id;
                            c->room_state = ROOM_SYNCING;

                            printf("[ROOM CHANGE] You've changed your room from %" PRIu32
                                   " to %" PRIu32 "\n",
                                   prev_room, c->room_id);

                            break;
                        }
                        case PKT_ENC_CHAT:
                        {
                            if (c->room_state != ROOM_READY)
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
