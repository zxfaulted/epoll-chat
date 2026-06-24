#include "client/client_commands.h"

#include "auth/auth.h"
#include "auth/key_bundle.h"
#include "client/client_send.h"
#include "crypto/crypto_core.h"
#include "e2e/client_room_session.h"
#include "e2e/room_crypto.h"
#include "transport/epoll_io.h"
#include "transport/packet_io.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

// 0 некритичная ошибка, клиент может продолжат работу
// -1 критичная ошибка, закрыть клиент
int handle_input(int epfd, Client* c, RoomSession* rooms, GeneratedKeys* gk, char* out_buf,
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

    if (c->auth_state == AUTH_NEW)
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

            return send_name_command(epfd, c, PKT_AUTH_BEGIN, login_name);
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

            return send_name_command(epfd, c, PKT_AUTH_BEGIN, default_name);
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

    if (c->auth_state != AUTH_READY)
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

    if (c->auth_state == AUTH_READY)
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
            unsigned long room_id = strtoul(out_buf + 6, &end, 0);
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
            if (room_id < 1 || room_id > MAX_ROOMS)
            {
                printf("[ERROR] INVALID ROOM ID\n");
                return 0;
            }

            if ((uint32_t)room_id == c->room_id)
            {
                printf("[LOCAL] You are already in room #%" PRIu32 "\n", c->room_id);
                return 0;
            }
            if (client_send_pkt_room_join_begin(epfd, c, room_id) < 0)
            {
                return -1;
            }
            c->room_state = ROOM_JOINING;
            return 0;
        }

        else if (strncmp(out_buf, "/create_room_password", 21) == 0)
        {
            uint32_t room_id;
            char     password[128];
            int n = sscanf(out_buf, "/create_room_password %" PRIu32 " %127s", &room_id, password);
            if (n != 2)
            {
                printf("[ERROR] NUMBER OF ARGUMENTS MUST BE 2\n");
                return 0;
            }
            if (room_id < 1 || room_id > MAX_ROOMS)
            {
                printf("[ERROR] ROOM ID IS OUT OF RANGE: %" PRIu32 "\n", room_id);
                return 0;
            }
            size_t password_len = strlen(password);
            if (password_len > MAX_PASSWORD_LEN)
            {
                fprintf(stderr, "MAXIMUM PASSWORD LENGTH IS 128 SYMBOLS\n");
                return 0;
            }
            if (password_len < MIN_PASSWORD_LEN)
            {
                fprintf(stderr, "MINIMUM PASSWORD LENGTH IS 4 SYMBOLS\n");
                return 0;
            }
            uint8_t room_key[ROOM_KEY_LEN];
            if (RAND_bytes(room_key, ROOM_KEY_LEN) != 1)
            {
                ossl_print_error("RAND_BYTES");
                return -1;
            }

            int ret = -1;
            ret     = client_send_pkt_room_create_password(epfd, c, room_id, password, room_key);
            OPENSSL_cleanse(room_key, ROOM_KEY_LEN);
            return ret;
        }

        else if (strncmp(out_buf, "/create_room", 12) == 0)
        {
            const char* p_room_id = out_buf + 13;
            uint32_t    room_id   = atoi(p_room_id);
            if (room_id < 1 || room_id > MAX_ROOMS)
            {
                printf("[ERROR] ROOM ID IS OUT OF RANGE\n");
                return 0;
            }
            return client_send_pkt_room_create(epfd, c, room_id);
        }

        else if (out_buf[0] == '/')
        {
            printf("[ERROR] Unknown command: %s\n", out_buf);
            printf("[LOCAL] Type /help to see supported commands.\n");
            return 0;
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
            if (client_send_encrypted_chat(epfd, c, room, (uint8_t*)out_buf, (uint16_t)bytes) < 0)
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

void print_help(Client* c)
{
    if (!c || c->auth_state != AUTH_READY)
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

int send_name_command(int epfd, Client* c, uint8_t pkt_type, const char* user_name)
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
        c->auth_state = AUTH_CLIENT_WAIT_REGISTER_CHALLENGE;
    }
    else if (pkt_type == PKT_AUTH_BEGIN)
    {
        c->auth_state = AUTH_CLIENT_WAIT_AUTH_CHALLENGE;
    }

    return 0;
}
