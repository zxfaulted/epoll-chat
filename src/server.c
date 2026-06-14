#include "auth.h"
#include "crypto.h"
#include "key_bundle.h"
#include "ksi.h"
#include "net.h"
#include "transport.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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

int main()
{
    int     ret       = -1;
    int     server_fd = -1;
    int     epfd      = -1;
    Server* server    = NULL;
    signal(SIGPIPE, SIG_IGN);
    OSSL_PROVIDER*     dflt = NULL;
    OSSL_PROVIDER*     gost = NULL;
    struct epoll_event events[MAX_EVENTS];

    int     clients_count = 0;
    Client* clients[MAX_CLIENTS];
    memset(clients, 0, sizeof(clients));
    uint32_t client_id  = 1;
    uint32_t message_id = 0;
    int      client_removed;

    PendingReg pr[MAX_PENDING_REGISTRATIONS];
    memset(&pr, 0, sizeof(pr));

    if (ossl_init_crypto(&dflt, &gost) < 0)
    {
        fprintf(stderr, "ossl_init_crypto failed\n");
        return -1;
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket");
        return -1;
    }

    struct sockaddr_in server_sa;
    socklen_t          server_len = sizeof(server_sa);
    memset(&server_sa, 0, server_len);
    server_sa.sin_addr.s_addr = INADDR_ANY;
    server_sa.sin_family      = AF_INET;
    server_sa.sin_port        = htons(SERVER_PORT);

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
    {
        perror("setsockopt");
        goto cleanup;
    }

    if (bind(server_fd, (struct sockaddr*)&server_sa, server_len) < 0)
    {
        perror("bind");
        goto cleanup;
    }

    if (listen(server_fd, SOMAXCONN) < 0)
    {
        perror("listen");
        goto cleanup;
    }

    if (set_nonblocking(server_fd) < 0)
    {
        perror("fcntl");
        goto cleanup;
    }
    server = malloc(sizeof(Server));
    if (server == NULL)
    {
        perror("server malloc");
        goto cleanup;
    }
    server->sa = server_sa;

    server->ei.fd   = server_fd;
    server->ei.item = SERVER_ITEM;

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events   = EPOLLIN;
    ev.data.ptr = server;

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0)
    {
        perror("epoll_create1");
        goto cleanup;
    }
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, server->ei.fd, &ev) < 0)
    {
        perror("epoll ADD server");
        goto cleanup;
    };

    while (1)
    {
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (nfds < 0)
        {
            perror("epoll_wait");
            goto cleanup;
        }
        for (int i = 0; i < nfds; i++)
        {
            client_removed   = 0;
            uint32_t cur_evs = events[i].events;

            EpollItem* ei = events[i].data.ptr;

            // появился новый клиент
            if (ei->item == SERVER_ITEM)
            {
                // Server* s = (Server*)ei;
                if (add_new_client(epfd, server_fd, clients, &clients_count, &client_id) < 0)
                {
                    continue;
                }
            }
            else if (ei->item == CLIENT_ITEM)
            {
                Client* c = (Client*)ei;
                if (cur_evs & EPOLLIN)
                {
                    switch (c->state)
                    {
                        uint8_t  msg[PAYLOAD_SIZE];
                        uint32_t msg_len;
                        int      rc;

                        case STATE_WAIT_NAME:
                        {
                            rc = recv_into_inbuf(c);
                            if (rc == 0)
                            {
                                break;
                            }
                            if (rc < 0)
                            {
                                if (rc == -1)
                                {
                                    if (disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id) < 0)
                                    {
                                        fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                    }
                                    client_removed = 1;
                                    break;
                                }
                                fprintf(stderr, "recv_into_buf PKT_NAME\n");
                                if (disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id) < 0)
                                {
                                    fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                }
                                client_removed = 1;
                                break;
                            }
                            Header h = {0};
                            rc       = try_pop_packet(c, &h, msg, &msg_len);
                            if (rc == 0)
                            {
                                break;
                            }
                            if (rc < 0)
                            {
                                if (rc == -1)
                                {
                                    if (disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id) < 0)
                                    {
                                        fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                    }
                                    client_removed = 1;
                                    break;
                                }
                                reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                              "POP_PACKET_ERROR", &message_id);
                                client_removed = 1;
                                break;
                            }

                            PacketState p_st = validate_packet_name(msg_len, &h);
                            if (p_st != PKT_OK)
                            {
                                char        res[100];
                                const char* p_st_str = packet_state_str(p_st);
                                snprintf(res, 100, "VALIDATE_PACKET_NAME ERROR: %s\n", p_st_str);

                                reject_packet(epfd, c, c->ei.fd, clients, &clients_count, res,
                                              &message_id);

                                client_removed = 1;
                                break;
                            }

                            char out[MAX_NAME_LEN + 1];
                            memset(out, 0, sizeof(out));
                            if (payload_to_str(msg, msg_len, out, MAX_NAME_LEN + 1) < 0)
                            {
                                if (send_server_error(epfd, c, "NAME IS TOO LONG", &message_id) < 0)
                                {
                                    disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id);
                                    client_removed = 1;
                                    break;
                                }
                                c->close_after_flush = 1;
                                break;
                            }
                            if (h.type == PKT_NAME)
                            {
                                if (!is_name_safe(out))
                                {
                                    reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                                  "BAD NAME", &message_id);
                                    client_removed = 1;
                                    break;
                                }
                                if (!ksi_exists(out))
                                {
                                    if (send_server_error(epfd, c, "YOU ARE NOT REGISTERED",
                                                          &message_id) < 0)
                                    {
                                        fprintf(stderr, "SEND_SERVER_ERROR FAILED\n");
                                        disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id);
                                        client_removed = 1;
                                        break;
                                    }

                                    break;
                                }
                                size_t out_len = strlen(out);
                                if (set_client_name(c, out, out_len) < 0)
                                {
                                    if (send_server_error(epfd, c, "COULDN'T SET CLIENT NAME",
                                                          &message_id) < 0)
                                    {
                                        disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id);
                                        client_removed = 1;
                                        break;
                                    }
                                    c->close_after_flush = 1;
                                    break;
                                }
                                if (server_send_challenge(epfd, c, c->id, c->challenge,
                                                          &message_id) < 0)
                                {
                                    fprintf(stderr, "server_send_challenge failed\n");
                                    disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id);
                                    client_removed = 1;
                                    break;
                                }
                                c->state = STATE_WAIT_AUTH_RESPONSE;
                                break;
                            }
                            if (h.type == PKT_REGISTER_BEGIN)
                            {
                                if (!is_name_safe(out))
                                {
                                    reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                                  "BAD NAME", &message_id);
                                    client_removed = 1;
                                    break;
                                }
                                if (ksi_exists(out))
                                {
                                    if (send_server_error(epfd, c, "YOU ARE REGISTERED ALREADY",
                                                          &message_id) < 0)
                                    {
                                        disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id);
                                        client_removed = 1;
                                        break;
                                    }

                                    break;
                                }
                                size_t out_len = strlen(out);
                                if (set_client_name(c, out, out_len) < 0)
                                {
                                    if (send_server_error(epfd, c, "COULDN'T SET CLIENT NAME",
                                                          &message_id) < 0)
                                    {
                                        disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id);
                                        client_removed = 1;
                                        break;
                                    }
                                    c->close_after_flush = 1;
                                    break;
                                }
                                if (find_in_pending_registrations(pr, c->name, c->id) >= 0)
                                {
                                    reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                                  "ANOTHER PENDING REGISTRATION ON THAT NAME",
                                                  &message_id);
                                    client_removed = 1;
                                    break;
                                }

                                uint8_t reg_challenge[CHALLENGE_LEN];
                                if (get_challenge(reg_challenge) < 0)
                                {
                                    fprintf(stderr, "get_challenge failed\n");
                                    if (send_server_error(epfd, c, "challenge generation failed",
                                                          &message_id) < 0)
                                    {
                                        disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id);
                                        client_removed = 1;
                                        break;
                                    }
                                    c->close_after_flush = 1;
                                    break;
                                }
                                if (server_send_registration_challenge(
                                        epfd, c, c->id, reg_challenge, &message_id) < 0)
                                {
                                    disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id);
                                    client_removed = 1;
                                    break;
                                }
                                if (add_pending_registration(pr, c->name, reg_challenge, c->id) < 0)
                                {
                                    disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id);
                                    client_removed = 1;
                                    break;
                                }
                            }

                            c->state = STATE_WAIT_REGISTER_COMMIT;
                            break;
                        }
                        case STATE_WAIT_REGISTER_COMMIT:
                        {
                            rc = recv_into_inbuf(c);
                            if (rc == 0)
                            {
                                break;
                            }
                            if (rc < 0)
                            {
                                if (rc == -1)
                                {
                                    if (disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id) < 0)
                                    {
                                        fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                    }
                                    client_removed = 1;
                                    break;
                                }
                                fprintf(stderr, "recv_into_buf PKT_NAME\n");
                                if (disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id) < 0)
                                {
                                    fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                }
                                client_removed = 1;
                                break;
                            }
                            Header h = {0};
                            rc       = try_pop_packet(c, &h, msg, &msg_len);
                            if (rc == 0)
                            {
                                break;
                            }
                            if (rc < 0)
                            {
                                if (rc == -1)
                                {
                                    if (disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id) < 0)
                                    {
                                        fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                    }
                                    client_removed = 1;
                                    break;
                                }
                                reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                              "POP_PACKET_ERROR", &message_id);
                                client_removed = 1;
                                break;
                            }
                            if (h.type != PKT_REGISTER_COMMIT)
                            {
                                reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                              "EXPECTED_REGISTER_COMMIT", &message_id);
                                client_removed = 1;
                                break;
                            }

                            if (h.sender_id != c->id || h.room_id != 0)
                            {
                                reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                              "BAD_REGISTER_COMMIT_HEADER", &message_id);
                                client_removed = 1;
                                break;
                            }

                            int i = find_in_pending_registrations(pr, c->name, c->id);
                            if (i < 0)
                            {
                                if (send_server_error(epfd, c, "NO PENDING REGISTRATION",
                                                      &message_id) < 0)
                                {
                                    disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id);
                                    client_removed = 1;
                                    break;
                                }
                                c->close_after_flush = 1;
                                break;
                            }

                            char reg_name[MAX_NAME_LEN + 1];
                            snprintf(reg_name, sizeof(reg_name), "%s", pr[i].name);

                            EVP_PKEY* identity_pub = NULL;
                            if (msg_len > UINT16_MAX)
                            {
                                fprintf(stderr, "payload too large\n");
                                break;
                            }
                            if (verify_register_commit(pr[i].id, pr[i].name, pr[i].challenge, msg,
                                                       (uint16_t)msg_len, &identity_pub) != 1 ||
                                !identity_pub)
                            {
                                remove_pending_registration(pr, pr[i].name, pr[i].id);
                                if (send_server_error(epfd, c, "verify_register_commit failed",
                                                      &message_id) < 0)
                                {
                                    disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id);
                                    client_removed = 1;
                                    break;
                                }
                                c->close_after_flush = 1;
                                break;
                            }

                            if (ksi_exists(reg_name))
                            {
                                EVP_PKEY_free(identity_pub);
                                identity_pub = NULL;
                                remove_pending_registration(pr, pr[i].name, pr[i].id);
                                if (send_server_error(epfd, c, "NAME ALREADY REGISTERED",
                                                      &message_id) < 0)
                                {
                                    disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id);
                                    client_removed = 1;
                                    break;
                                }
                                c->close_after_flush = 1;
                                break;
                            }

                            if (ksi_make_entry(reg_name, identity_pub) < 0)
                            {
                                EVP_PKEY_free(identity_pub);
                                identity_pub = NULL;

                                remove_pending_registration(pr, pr[i].name, pr[i].id);

                                if (send_server_error(epfd, c, "KSI WRITE FAILED", &message_id) < 0)
                                {
                                    disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id);
                                    client_removed = 1;
                                    break;
                                }
                                c->close_after_flush = 1;
                                break;
                            }

                            EVP_PKEY_free(identity_pub);
                            identity_pub = NULL;

                            remove_pending_registration(pr, pr[i].name, pr[i].id);

                            if (send_server_register_ok(c, c->room_id, reg_name, c->id,
                                                        &message_id) < 0)
                            {
                                fprintf(stderr, "send_server_register_ok\n");
                                disconnect_client(epfd, c, clients, &clients_count, &message_id);
                                client_removed = 1;
                                break;
                            }

                            if (set_epollout_to_client(epfd, c) < 0)
                            {
                                fprintf(stderr, "set_epollout_to_client\n");
                                disconnect_client(epfd, c, clients, &clients_count, &message_id);
                                client_removed = 1;
                                break;
                            }
                            c->state = STATE_WAIT_KEY_BUNDLE;
                            break;
                        }
                        case STATE_WAIT_AUTH_RESPONSE:
                        {
                            rc = recv_into_inbuf(c);
                            if (rc == 0)
                            {
                                break;
                            }
                            if (rc < 0)
                            {
                                if (rc == -1)
                                {
                                    if (disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id) < 0)
                                    {
                                        fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                    }
                                    client_removed = 1;
                                    break;
                                }
                                fprintf(stderr, "recv_into_buf PKT_NAME");
                                if (disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id) < 0)
                                {
                                    fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                }
                                client_removed = 1;
                                break;
                            }
                            Header h = {0};
                            rc       = try_pop_packet(c, &h, msg, &msg_len);
                            if (rc == 0)
                            {
                                break;
                            }
                            if (rc < 0)
                            {
                                if (rc == -1)
                                {
                                    if (disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id) < 0)
                                    {
                                        fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                    }
                                    client_removed = 1;
                                    break;
                                }
                                reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                              "POP_PACKET_ERROR", &message_id);
                                client_removed = 1;
                                break;
                            }
                            if (h.type != PKT_AUTH_RESPONSE)
                            {
                                reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                              "POP_PACKET_ERROR", &message_id);
                                client_removed = 1;
                                break;
                            }

                            EVP_PKEY* public_key = ksi_read_key(c->name);
                            if (!public_key)
                            {
                                fprintf(stderr, "ksi_read_key failed\n");
                                break;
                            }
                            EVP_PKEY_free(public_key);
                            if (msg_len > UINT16_MAX)
                            {
                                fprintf(stderr, "payload too large\n");
                                break;
                            }

                            int verification_response =
                                server_verify_challenge(c, msg, (uint16_t)msg_len);
                            if (verification_response == 0)
                            {
                                fprintf(stderr, "SIGN IS WRON\n");
                                disconnect_client(epfd, c, clients, &clients_count, &message_id);
                                client_removed = 1;
                                break;
                            }
                            else if (verification_response < 0)
                            {
                                fprintf(stderr, "server_verify_challenge failed\n");
                                disconnect_client(epfd, c, clients, &clients_count, &message_id);
                                client_removed = 1;
                                break;
                            }

                            if (send_server_register_ok(c, c->room_id, c->name, c->id,
                                                        &message_id) < 0)
                            {
                                fprintf(stderr, "send_server_register_ok failed\n");
                                disconnect_client(epfd, c, clients, &clients_count, &message_id);
                                client_removed = 1;
                                break;
                            }
                            if (set_epollout_to_client(epfd, c) < 0)
                            {
                                fprintf(stderr, "set_epollout_to_client\n");
                                disconnect_client(epfd, c, clients, &clients_count, &message_id);
                                client_removed = 1;
                                break;
                            }
                            c->state = STATE_WAIT_KEY_BUNDLE;
                            break;
                        }
                        case STATE_WAIT_KEY_BUNDLE:
                        {
                            // 1. Проверить размер payload.
                            // 2. Сохранить raw key bundle в Client.
                            // 3. Перевести клиента в STATE_READY.
                            // 4. Отправить новому клиенту список участников.
                            // 5. Отправить новому клиенту key bundles всех текущих участников
                            // комнаты.
                            // 6. Разослать key bundle нового клиента старым участникам.
                            // 7. Разослать PKT_JOIN.
                            // 8. Отправить новому клиенту PKT_ROOM_SYNC_DONE.
                            rc = recv_into_inbuf(c);
                            if (rc == 0)
                            {
                                break;
                            }
                            if (rc < 0)
                            {
                                if (rc == -1)
                                {
                                    if (disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id) < 0)
                                    {
                                        fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                    }
                                    client_removed = 1;
                                    break;
                                }
                                fprintf(stderr, "recv_into_buf STATE_WAIT_KEY_BUNDLE");
                                if (disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id) < 0)
                                {
                                    fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                }
                                client_removed = 1;
                                break;
                            }

                            Header h = {0};
                            rc       = try_pop_packet(c, &h, msg, &msg_len);
                            if (rc == 0)
                            {
                                break;
                            }
                            if (rc < 0)
                            {
                                if (rc == -1)
                                {
                                    if (disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id) < 0)
                                    {
                                        fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                    }
                                    client_removed = 1;
                                    break;
                                }
                                reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                              "POP_PACKET_ERROR", &message_id);
                                client_removed = 1;
                                break;
                            }
                            if (h.type != PKT_ENC_KEY_BUNDLE)
                            {
                                if (send_server_error(epfd, c, "EXPECTED PKT_ENC_KEY_BUNDLE",
                                                      &message_id) < 0)
                                {
                                    disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id);
                                    client_removed = 1;
                                    break;
                                }
                                c->close_after_flush = 1;
                                break;
                            }
                            // 1. Проверить размер payload.
                            if (msg_len == 0)
                            {
                                fprintf(stderr, "msg_len WRONG\n");
                                if (disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id) < 0)
                                {
                                    fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                }
                                client_removed = 1;
                                break;
                            }
                            if (msg_len > UINT16_MAX)
                            {
                                fprintf(stderr, "payload too large\n");
                                break;
                            }
                            if (verify_key_bundle(msg, (uint16_t)msg_len) != 1)
                            {
                                fprintf(stderr, "did not pass verify_key_bundle\n");
                                if (disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id) < 0)
                                {
                                    fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                }
                                client_removed = 1;
                                break;
                            }
                            if (msg_len > UINT16_MAX)
                            {
                                fprintf(stderr, "payload too large\n");
                                break;
                            }
                            KeyBundle* kb = deserialize_key_bundle_full(msg, (uint16_t)msg_len);
                            if (!kb)
                            {
                                fprintf(stderr, "deserialize_key_bundle_full failed\n");
                                if (disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id) < 0)
                                {
                                    fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                }
                                client_removed = 1;
                                break;
                            }
                            if (msg_len > UINT16_MAX)
                            {
                                fprintf(stderr, "payload too large\n");
                                break;
                            }
                            if (key_bundle_matches_ksi(c, msg, (uint16_t)msg_len) != 1)
                            {
                                if (send_server_error(epfd, c, "KEY_BUNDLE_KSI_MISMATCH",
                                                      &message_id) < 0)
                                {
                                    disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id);
                                    client_removed = 1;
                                    break;
                                }
                                kb_free(kb);
                                c->close_after_flush = 1;
                                break;
                            }

                            if (h.sender_id != c->id || h.room_id != c->room_id ||
                                kb->client_id != c->id)
                            {
                                if (send_server_error(epfd, c, "CLIENT_ID MISMATCH", &message_id) <
                                    0)
                                {
                                    disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id);
                                    client_removed = 1;
                                    break;
                                }
                                c->close_after_flush = 1;
                                kb_free(kb);
                                break;
                            }
                            kb_free(kb);

                            // 2. Сохранить raw key bundle в Client.
                            c->raw_kb = OPENSSL_malloc(msg_len);
                            if (!c->raw_kb)
                            {
                                ossl_print_error("OPENSSL_malloc");
                                disconnect_client(epfd, c, clients, &clients_count, &message_id);
                                client_removed = 1;
                                break;
                            }
                            memcpy(c->raw_kb, msg, msg_len);
                            c->raw_kb_len = msg_len;
                            c->has_kb     = 1;

                            // 3. Перевести клиента в STATE_READY.
                            c->state = STATE_READY;

                            // 4. Отправить новому клиенту список участников.
                            if (send_server_ready_users(c, c->room_id, clients, clients_count,
                                                        &message_id) < 0)
                            {
                                fprintf(stderr, "send_server_ready_key_bundles failed\n");
                                disconnect_client(epfd, c, clients, &clients_count, &message_id);
                                client_removed = 1;
                                break;
                            }
                            // 5. Отправить новому клиенту key bundles всех текущих участников
                            // комнаты
                            if (send_server_ready_key_bundles(epfd, c, clients, &clients_count,
                                                              &message_id) < 0)
                            {
                                fprintf(stderr, "send_server_ready_key_bundles failed\n");
                                disconnect_client(epfd, c, clients, &clients_count, &message_id);
                                client_removed = 1;
                                break;
                            }

                            // 6. Разослать key bundle нового клиента старым участникам.
                            if (send_server_new_key_bundle(epfd, c, clients, clients_count,
                                                           &message_id) < 0)
                            {
                                {
                                    fprintf(stderr, "send_server_new_key_bundle failed\n");
                                    disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id);
                                    client_removed = 1;
                                    break;
                                }
                            }
                            // 7. Разослать PKT_JOIN.
                            broadcast_user_event(epfd, c, c->room_id, clients, &clients_count,
                                                 PKT_JOIN, &message_id);
                            // 8. Отправить новому клиенту PKT_ROOM_SYNC_DONE.
                            if (send_server_user_event(c, c->room_id, PKT_ROOM_SYNC_DONE, c->name,
                                                       c->id, &message_id) < 0)
                            {
                                fprintf(stderr,
                                        "send_server_user_event PKT_ROOM_SYNC_DONE failed\n");
                                disconnect_client(epfd, c, clients, &clients_count, &message_id);
                                client_removed = 1;
                                break;
                            }

                            if (set_epollout_to_client(epfd, c) < 0)
                            {
                                fprintf(stderr, "set_epollout_to_client failed\n");
                                disconnect_client(epfd, c, clients, &clients_count, &message_id);
                                client_removed = 1;
                                break;
                            }

                            c->state = STATE_READY;
                            break;
                        }
                        case STATE_WAIT_ROOM_KEY:
                            break;
                        case STATE_WAIT_AUTH_CHALLENGE:
                            break;
                        case STATE_WAIT_REGISTER_OK:
                            break;
                        case STATE_WAIT_REGISTER_CHALLENGE:
                            break;
                        case STATE_READY:
                            rc = recv_into_inbuf(c);
                            if (rc < 0)
                            {
                                if (rc == -1)
                                {
                                    if (disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id) < 0)
                                    {
                                        fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                    }
                                    client_removed = 1;
                                    break;
                                }
                                if (rc == -2)
                                {
                                    perror("recv_into_buf PKT_CHAT");
                                }
                                if (disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id) < 0)
                                {
                                    fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                }
                                client_removed = 1;
                                break;
                            }
                            while (1)
                            {
                                Header h;
                                memset(&h, 0, sizeof(h));
                                rc = try_pop_packet(c, &h, msg, &msg_len);
                                if (rc == 0)
                                {
                                    break;
                                }
                                if (rc < 0)
                                {
                                    if (rc == -1)
                                    {
                                        if (disconnect_client(epfd, c, clients, &clients_count,
                                                              &message_id) < 0)
                                        {
                                            fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                        }
                                        client_removed = 1;
                                        break;
                                    }
                                    fprintf(stderr, "try_pop_packet broadcast");
                                    if (disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id) < 0)
                                    {
                                        fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                    }
                                    client_removed = 1;
                                    break;
                                }
                                switch (h.type)
                                {
                                    case PKT_CHAT:
                                    {
                                        PacketState p_st = validate_packet_chat(msg_len, &h);
                                        if (p_st == PKT_OK)
                                        {
                                            if (h.room_id != c->room_id)
                                            {
                                                if (send_server_error(epfd, c,
                                                                      "YOU ARE NOT IN THIS ROOM\n",
                                                                      &message_id) < 0)
                                                {
                                                    disconnect_client(epfd, c, clients,
                                                                      &clients_count, &message_id);
                                                    client_removed = 1;
                                                    break;
                                                }
                                                c->close_after_flush = 1;
                                                break;
                                            }
                                            Header out;
                                            memset(&out, 0, sizeof(out));
                                            out.version    = h.version;
                                            out.type       = h.type;
                                            out.flags      = h.flags;
                                            out.sender_id  = c->id;
                                            out.room_id    = c->room_id;
                                            out.timestamp  = (uint64_t)time(NULL);
                                            out.message_id = next_message_id(&message_id);

                                            printf("[room=%" PRIu32 "] %s#%" PRIu32 ": %.*s\n",
                                                   c->room_id, c->name, c->id, (int)msg_len, msg);
                                            broadcast_message(epfd, c, &out, clients,
                                                              &clients_count, msg, msg_len,
                                                              &message_id);
                                        }
                                        else
                                        {
                                            const char* p_st_str = packet_state_str(p_st);
                                            reject_packet(epfd, c, c->ei.fd, clients,
                                                          &clients_count, p_st_str, &message_id);
                                            client_removed = 1;
                                            break;
                                        }
                                        break;
                                    }
                                    case PKT_ENC_ROOM_KEY:
                                    {
                                        if (forward_room_key_packet(epfd, clients, clients_count, c,
                                                                    &h, msg, msg_len,
                                                                    &message_id) < 0)
                                        {
                                            fprintf(stderr, "forward_room_key_packet\n");
                                            reject_packet(
                                                epfd, c, c->ei.fd, clients, &clients_count,
                                                "forward_room_key_packet failed", &message_id);
                                            client_removed = 1;
                                            break;
                                        }
                                        break;
                                    }
                                    case PKT_ROOM_CHANGE:
                                    {
                                        PacketState p_st = validate_packet_room_change(msg_len, &h);

                                        if (p_st != PKT_OK)
                                        {
                                            if (send_server_error(epfd, c, packet_state_str(p_st),
                                                                  &message_id) < 0)
                                            {
                                                disconnect_client(epfd, c, clients, &clients_count,
                                                                  &message_id);
                                                client_removed = 1;
                                                break;
                                            }
                                            c->close_after_flush = 1;
                                            break;
                                        }
                                        if (h.room_id == c->room_id)
                                        {
                                            if (send_server_user_event(c, c->room_id,
                                                                       PKT_ROOM_CHANGE_OK, c->name,
                                                                       c->id, &message_id) < 0)
                                            {
                                                disconnect_client(epfd, c, clients, &clients_count,
                                                                  &message_id);
                                                client_removed = 1;
                                                break;
                                            }
                                            if (set_epollout_to_client(epfd, c) < 0)
                                            {
                                                disconnect_client(epfd, c, clients, &clients_count,
                                                                  &message_id);
                                                client_removed = 1;
                                                break;
                                            }
                                            break;
                                        }
                                        // рассылка PKT_LEAVE в прошлую комнату
                                        broadcast_user_event(epfd, c, c->room_id, clients,
                                                             &clients_count, PKT_LEAVE,
                                                             &message_id);
                                        // смена комнаты для клиента
                                        uint32_t prev_room_id = c->room_id;
                                        c->room_id            = h.room_id;
                                        printf("Client %s#%" PRIu32 " changed room from %" PRIu32
                                               " to %" PRIu32 "\n",
                                               c->name, c->id, prev_room_id, c->room_id);
                                        // рассылка PKT_JOIN в новую комнату
                                        broadcast_user_event(epfd, c, c->room_id, clients,
                                                             &clients_count, PKT_JOIN, &message_id);
                                        // подтверждение смены комнаты клиенту
                                        if (send_server_user_event(c, c->room_id,
                                                                   PKT_ROOM_CHANGE_OK, c->name,
                                                                   c->id, &message_id) < 0)
                                        {
                                            disconnect_client(epfd, c, clients, &clients_count,
                                                              &message_id);
                                            client_removed = 1;
                                            break;
                                        }
                                        // список готовых пользователей для вошедшего
                                        if (send_server_ready_users(c, c->room_id, clients,
                                                                    clients_count, &message_id) < 0)
                                        {
                                            disconnect_client(epfd, c, clients, &clients_count,
                                                              &message_id);
                                            client_removed = 1;
                                            break;
                                        }
                                        // key bundles существующих для вошедшего
                                        if (send_server_ready_key_bundles(
                                                epfd, c, clients, &clients_count, &message_id) < 0)
                                        {
                                            disconnect_client(epfd, c, clients, &clients_count,
                                                              &message_id);
                                            client_removed = 1;
                                            break;
                                        }
                                        // key bundle вошедшего для существующих
                                        if (send_server_new_key_bundle(
                                                epfd, c, clients, clients_count, &message_id) < 0)
                                        {
                                            disconnect_client(epfd, c, clients, &clients_count,
                                                              &message_id);
                                            client_removed = 1;
                                            break;
                                        }
                                        // PKT_ROOM_SYNC_DONE вошедшему
                                        if (send_server_user_event(c, c->room_id,
                                                                   PKT_ROOM_SYNC_DONE, c->name,
                                                                   c->id, &message_id) < 0)
                                        {
                                            disconnect_client(epfd, c, clients, &clients_count,
                                                              &message_id);
                                            client_removed = 1;
                                            break;
                                        }
                                        if (set_epollout_to_client(epfd, c) < 0)
                                        {
                                            disconnect_client(epfd, c, clients, &clients_count,
                                                              &message_id);
                                            client_removed = 1;
                                            break;
                                        }
                                        c->state = STATE_READY;
                                        break;
                                    }
                                    case PKT_ENC_CHAT:
                                    {
                                        if (c->room_id != h.room_id)
                                        {
                                            if (send_server_error(
                                                    epfd, c,
                                                    "client and header room_id are not the same",
                                                    &message_id) < 0)
                                            {
                                                disconnect_client(epfd, c, clients, &clients_count,
                                                                  &message_id);
                                                client_removed = 1;
                                                break;
                                            }
                                            c->close_after_flush = 1;
                                            break;
                                        }
                                        if (msg_len < ENC_OVERHEAD || msg_len > PAYLOAD_SIZE)
                                        {
                                            if (send_server_error(epfd, c, "msg_len too large",
                                                                  &message_id) < 0)
                                            {
                                                disconnect_client(epfd, c, clients, &clients_count,
                                                                  &message_id);
                                                client_removed = 1;
                                                break;
                                            }
                                            c->close_after_flush = 1;
                                            break;
                                        }
                                        Header h_out     = {0};
                                        h_out.flags      = 0;
                                        h_out.message_id = next_message_id(&message_id);
                                        h_out.room_id    = c->room_id;
                                        h_out.sender_id  = c->id;
                                        h_out.timestamp  = (uint64_t)time(NULL);
                                        h_out.type       = PKT_ENC_CHAT;
                                        h_out.version    = 1;
                                        broadcast_message(epfd, c, &h_out, clients, &clients_count,
                                                          msg, msg_len, &message_id);
                                        break;
                                    }

                                    default:
                                    {
                                        char reply[256];
                                        snprintf(reply, 256, "UNSUPPORTED PACKET TYPE: %s",
                                                 packet_type_str(h.type));
                                        reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                                      (const char*)reply, &message_id);
                                        client_removed = 1;
                                        break;
                                    }
                                }
                                if (client_removed)
                                {
                                    break;
                                }
                            }
                    }
                }
                if (client_removed)
                {
                    break;
                }
                if (cur_evs & EPOLLOUT)
                {
                    int rc = flush_send(c);
                    if (rc < 0)
                    {
                        if (rc == -1)
                        {
                            if (disconnect_client(epfd, c, clients, &clients_count, &message_id) <
                                0)
                            {
                                fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                            }
                            client_removed = 1;
                            break;
                        }
                        if (disconnect_client(epfd, c, clients, &clients_count, &message_id) < 0)
                        {
                            fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                        }
                        client_removed = 1;
                        continue;
                    }
                    if (c->conn.out_len == 0)
                    {
                        if (c->close_after_flush)
                        {
                            disconnect_client(epfd, c, clients, &clients_count, &message_id);
                            client_removed = 1;
                            continue;
                        }
                        if (unset_epollout_to_client(epfd, c) < 0)
                        {
                            if (disconnect_client(epfd, c, clients, &clients_count, &message_id) <
                                0)
                            {
                                fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                            }
                            client_removed = 1;
                            continue;
                        }
                    }
                }
                if (client_removed)
                {
                    break;
                }
                // EPOLLHUP - соединение умерло полностью
                // EPOLLRDHUP - клиент больше не пишет, но может читать
                if (cur_evs & EPOLLHUP || cur_evs & EPOLLRDHUP || cur_evs & EPOLLERR)
                {
                    if (disconnect_client(epfd, c, clients, &clients_count, &message_id) < 0)
                    {
                        fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                    }
                    client_removed = 1;
                    break;
                }
            }
        }
    }
    ret = 0;
cleanup:
    for (int i = 0; i < clients_count; i++)
    {
        if (clients[i])
        {
            OPENSSL_clear_free(clients[i]->raw_kb, clients[i]->raw_kb_len);
            close(clients[i]->ei.fd);
            free(clients[i]);
            clients[i] = NULL;
        }
    }
    ossl_destroy_crypto(&dflt, &gost);

    if (server_fd >= 0)
    {
        close(server_fd);
    }
    if (epfd >= 0)
    {
        close(epfd);
    }
    if (server)
    {
        free(server);
    }

    return ret;
}