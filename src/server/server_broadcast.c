#include "server/server_broadcast.h"

#include "auth/key_bundle.h"
#include "server/server_clients.h"
#include "server/server_send.h"
#include "transport/epoll_io.h"
#include "transport/packet_io.h"

#include <stdio.h>
#include <string.h>

void broadcast_message(int epfd, Client* c, Header* h, Client* clients[], int* clients_count,
                       const uint8_t msg[], uint32_t len, ServerRoom* server_rooms,
                       uint32_t rooms_count, uint32_t* message_id)
{

    int i = 0;
    while (i < *clients_count)
    {
        if (clients[i]->ei.fd == c->ei.fd)
        {
            i++;
            continue;
        }

        if (clients[i]->room_state != ROOM_READY)
        {
            i++;
            continue;
        }
        if (clients[i]->room_id != h->room_id)
        {
            i++;
            continue;
        }
        if (enqueue_packet(clients[i], h, msg, len) < 0)
        {
            i++;
            continue;
        }
        // без i++ для учета swap-delete
        if (set_epollout_to_client(epfd, clients[i]) < 0)
        {
            perror("set_epollout_to_client");
            disconnect_client(epfd, clients[i], clients, clients_count, server_rooms, rooms_count,
                              message_id);
            continue;
        }
        i++;
    }
}

void broadcast_user_event(int epfd, Client* skip, uint32_t room_id, Client* clients[],
                          int* clients_count, PacketType type, ServerRoom* server_rooms,
                          uint32_t rooms_count, uint32_t* message_id)
{
    if (!skip || !clients || !clients_count || !message_id)
    {
        return;
    }
    uint32_t skip_id                     = skip->id;
    char     skip_name[MAX_NAME_LEN + 1] = {0};
    memcpy(skip_name, skip->name, MAX_NAME_LEN);
    skip_name[MAX_NAME_LEN] = '\0';

    int i = 0;
    while (i < *clients_count)
    {
        if (clients[i] == skip || clients[i]->id == skip_id)
        {
            i++;
            continue;
        }

        if (clients[i]->room_state != ROOM_READY)
        {
            i++;
            continue;
        }
        if (clients[i]->room_id != room_id)
        {
            i++;
            continue;
        }
        if (send_server_user_event(clients[i], room_id, type, skip_name, skip_id, message_id) < 0)
        {
            i++;
            continue;
        }
        // если сервер не смог включить epollout, значит, не может надежно обслуживать соединение
        // поэтому его закрываем
        if (set_epollout_to_client(epfd, clients[i]) < 0)
        {
            perror("set_epollout_to_client");
            disconnect_client(epfd, clients[i], clients, clients_count, server_rooms, rooms_count,
                              message_id);
            continue;
        }
        i++;
    }
}

int send_server_ready_users(Client* c, uint32_t room_id, Client* clients[], int clients_count,
                            uint32_t* message_id)
{
    if (!c || !clients)
    {
        return -1;
    }
    for (int i = 0; i < clients_count; i++)
    {
        if (clients[i] && clients[i]->room_state == ROOM_READY && c != clients[i] &&
            clients[i]->room_id == room_id)
        {
            if (send_server_user_event(c, room_id, PKT_JOIN, clients[i]->name, clients[i]->id,
                                       message_id) < 0)
            {
                return -1;
            }
        }
    }
    return 0;
}

int send_server_ready_key_bundles(int epfd, Client* c, Client* clients[], int* clients_count,
                                  uint32_t* message_id)
{
    if (!c || !clients)
    {
        return -1;
    }
    for (int i = 0; i < *clients_count; i++)
    {
        if (clients[i] && clients[i]->room_state == ROOM_READY && c != clients[i] &&
            clients[i]->room_id == c->room_id && clients[i]->has_kb == 1)
        {
            if (send_kb(c, clients[i]->raw_kb, clients[i]->raw_kb_len, clients[i]->id,
                        clients[i]->room_id, message_id) < 0)
            {
                fprintf(stderr, "send_kb failed\n");
                return -1;
            }
            if (set_epollout_to_client(epfd, c) < 0)
            {
                return -1;
            }
        }
    }
    return 0;
}

// рассылка key bundle вошедшего всем существующим в данной комнате
int send_server_new_key_bundle(int epfd, Client* c, Client* clients[], int clients_count,
                               uint32_t* message_id)
{

    if (!c || !clients)
    {
        return -1;
    }
    for (int i = 0; i < clients_count; i++)
    {
        if (clients[i] && clients[i]->room_state == ROOM_READY && c != clients[i] &&
            clients[i]->room_id == c->room_id && clients[i]->has_kb == 1)
        {
            if (send_kb(clients[i], c->raw_kb, c->raw_kb_len, c->id, c->room_id, message_id) < 0)
            {
                fprintf(stderr, "send_kb failed\n");
                return -1;
            }
            if (set_epollout_to_client(epfd, clients[i]) < 0)
            {
                fprintf(stderr, "send_kb failed\n");
                return -1;
            }
        }
    }
    return 0;
}
