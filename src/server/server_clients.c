#include "server/server_clients.h"

#include "server/server_broadcast.h"
#include "server/server_send.h"
#include "transport/tcp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

int add_new_client(int epfd, int server_fd, Client* clients[], int* clients_count,
                   uint32_t* client_id)
{
    while (1)
    {
        if ((*clients_count) >= MAX_CLIENTS)
        {
            fprintf(stderr, "too many clients");
            return -1;
        }
        struct sockaddr_in new_client_sa;
        socklen_t          new_client_len = sizeof(new_client_sa);
        memset(&new_client_sa, 0, new_client_len);
        int new_client_fd = accept(server_fd, (struct sockaddr*)&new_client_sa, &new_client_len);
        if (new_client_fd < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return 0;
            }
            return -1;
        }

        if (set_nonblocking(new_client_fd) < 0)
        {
            close(new_client_fd);
            return -1;
        }

        Client* new_client = malloc(sizeof(Client));
        if (!new_client)
        {
            close(new_client_fd);
            return -1;
        }
        memset(new_client, 0, sizeof(Client));
        new_client->id         = (*client_id)++;
        new_client->sa         = new_client_sa;
        new_client->ei.item    = CLIENT_ITEM;
        new_client->ei.fd      = new_client_fd;
        new_client->auth_state = AUTH_NEW;
        new_client->name[0]    = '\0';
        new_client->room_id    = 1;

        struct epoll_event ev;
        ev.events   = EPOLLIN | EPOLLHUP | EPOLLRDHUP;
        ev.data.ptr = new_client;

        if (epoll_ctl(epfd, EPOLL_CTL_ADD, new_client_fd, &ev) < 0)
        {
            perror("epoll_ctl ADD new_client");
            close(new_client_fd);
            free(new_client);
            return -1;
        };
        clients[(*clients_count)++] = new_client;

        printf("[CONNECT] Client #%" PRIu32 "\n", new_client->id);
    }
}

Client* find_client(Client* clients[], int clients_count, uint32_t client_id)
{
    for (int i = 0; i < clients_count; i++)
    {
        if (clients[i] && clients[i]->id == client_id)
        {
            return clients[i];
        }
    }
    return NULL;
}

int is_name_taken(Client* clients[], int clients_count, const char* name, size_t name_len)
{
    for (int i = 0; i < clients_count; i++)
    {
        if ((clients[i] && clients[i]->auth_state == AUTH_READY) &&
            (strlen(clients[i]->name) == name_len) &&
            (memcmp(clients[i]->name, name, name_len) == 0))
        {
            return 1;
        }
    }
    return 0;
}

static void remove_client(int epfd, int cur_fd, Client* clients[], int* clients_count)
{

    for (int i = 0; i < *clients_count; i++)
    {
        if (clients[i] && clients[i]->ei.fd == cur_fd)
        {
            Client* temp                = clients[i];
            clients[i]                  = clients[*clients_count - 1];
            clients[*clients_count - 1] = NULL;
            (*clients_count)--;

            printf("[DISCONNECT] Client #%" PRIu32 "\n", temp->id);

            if (epoll_ctl(epfd, EPOLL_CTL_DEL, cur_fd, NULL) < 0)
            {
                perror("epoll_ctl DEL");
            }
            close(cur_fd);
            OPENSSL_free(temp->raw_kb);
            free(temp);
            break;
        }
    }
}

int disconnect_client(int epfd, Client* c, Client* clients[], int* clients_count, ServerRoom* rooms,
                      uint32_t rooms_count, uint32_t* message_id)
{
    if (!c || !clients)
    {
        return -1;
    }
    uint32_t room_id = c->room_id;

    if (c->room_state == ROOM_READY && c->name[0] != '\0')
    {
        broadcast_user_event(epfd, c, room_id, clients, clients_count, PKT_LEAVE, rooms,
                             rooms_count, message_id);
    }

    remove_client(epfd, c->ei.fd, clients, clients_count);

    if (server_room_is_empty(clients, *clients_count, room_id))
    {
        server_room_delete_by_id(rooms, rooms_count, room_id);
    }
    return 0;
}

int server_room_is_empty(Client* clients[], int clients_count, uint32_t room_id)
{
    if (!clients)
    {
        return 1;
    }

    for (int i = 0; i < clients_count; ++i)
    {
        Client* client = clients[i];

        if (!client)
        {
            continue;
        }

        if (client->auth_state != AUTH_READY)
        {
            continue;
        }

        if (client->room_state != ROOM_READY)
        {
            continue;
        }

        if (client->room_id == room_id)
        {
            return 0;
        }
    }

    return 1;
}

uint32_t clients_leader_id(Client** clients, int clients_count, uint32_t room_id)
{
    if (!clients)
    {
        return 0;
    }
    uint32_t leader_id = 0;
    for (int i = 0; i < clients_count; ++i)
    {
        if (clients[i]->room_id != room_id)
        {
            continue;
        }
        if (clients[i]->auth_state != AUTH_READY || clients[i]->room_state != ROOM_READY)
        {
            continue;
        }
        if (clients[i]->id < leader_id || leader_id == 0)
        {
            leader_id = clients[i]->id;
        }
    }
    return leader_id;
}

int set_client_name(Client* c, const char* msg, size_t msg_len)
{
    if (msg_len == 0 || msg_len > MAX_NAME_LEN)
    {
        return -1;
    }

    memcpy(c->name, msg, msg_len);
    c->name[msg_len] = '\0';

    return 0;
}

int active_name_exists(Client* clients[], int clients_count, const char* name)
{
    if (!clients || !name)
    {
        return 0;
    }

    for (int i = 0; i < clients_count; ++i)
    {
        if (!clients[i])
        {
            continue;
        }

        if (clients[i]->auth_state == AUTH_READY && strcmp(clients[i]->name, name) == 0)
        {
            return 1;
        }
    }

    return 0;
}