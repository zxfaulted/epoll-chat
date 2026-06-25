#include "client/client_commands.h"

#include "auth/auth.h"
#include "auth/key_bundle.h"
#include "client/client_send.h"
#include "crypto/crypto_core.h"
#include "e2e/client_room_session.h"
#include "e2e/room_crypto.h"
#include "transport/epoll_io.h"
#include "transport/packet_io.h"
#include "ui/ui.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

// 0 некритичная ошибка, клиент может продолжат работу
// -1 критичная ошибка, закрыть клиент
int handle_input(int epfd, Client* c, RoomSession* rooms, GeneratedKeys* gk, char* out_buf,
                 ssize_t bytes, const char* default_name, int* registration_in_progress,
                 int* generated_keys_for_registration, int* awaiting_create_room_password,
                 uint32_t* pending_password_room_id)
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
        print_help(c, default_name);
        return 0;
    }

    if (c->auth_state == AUTH_NEW)
    {
        if (strcmp(out_buf, "1") == 0)
        {
            snprintf(out_buf, BUF_SIZE, "/login");
        }

        if (strcmp(out_buf, "2") == 0)
        {
            snprintf(out_buf, BUF_SIZE, "/register");
        }

        if (strcmp(out_buf, "3") == 0)
        {
            ui_print_help_logged_out(default_name);
            return 0;
        }
        if (strncmp(out_buf, "/register ", 10) == 0)
        {
            const char* reg_name = out_buf + 10;

            if (reg_name[0] == '\0')
            {
                ui_print_error("Usage: /register NAME");
                return 0;
            }

            if (strlen(reg_name) > MAX_NAME_LEN)
            {
                ui_print_error("NAME IS TOO LONG");
                return 0;
            }

            clear_generated_keys(gk);

            if (keys_exist(reg_name) == 1)
            {
                if (load_keys_for_name(gk, reg_name) < 0)
                {
                    ui_print_error("Failed to load local keys for '%s'", reg_name);
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
                ui_print_error("NAME IS TOO LONG");
                return 0;
            }

            clear_generated_keys(gk);

            if (keys_exist(default_name) == 1)
            {
                if (load_keys_for_name(gk, default_name) < 0)
                {
                    ui_print_error("Failed to load local keys for '%s'", default_name);
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
                ui_print_error("Usage: /login NAME\n");
                return 0;
            }

            if (strlen(login_name) > MAX_NAME_LEN)
            {
                ui_print_error("NAME IS TOO LONG\n");
                return 0;
            }

            if (keys_exist(login_name) != 1)
            {
                ui_print_error("No local keys for '%s'. Use /register %s first.", login_name,
                               login_name);
                return 0;
            }

            if (load_keys_for_name(gk, login_name) < 0)
            {
                ui_print_error("Failed to load local keys for '%s'", login_name);
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
                ui_print_error("No local keys for '%s'. Use /register %s first.\n", default_name,
                               default_name);
                return 0;
            }

            if (load_keys_for_name(gk, default_name) < 0)
            {
                ui_print_error("Failed to load local keys for '%s'\n", default_name);
                return 0;
            }

            *registration_in_progress        = 0;
            *generated_keys_for_registration = 0;

            return send_name_command(epfd, c, PKT_AUTH_BEGIN, default_name);
        }

        if (out_buf[0] == '/')
        {
            ui_print_error("Unknown command: %s", out_buf);
            ui_print_local("Type /help to see supported commands.");
            return 0;
        }

        ui_print_local("Message was not sent. You are not logged in.");
        ui_print_local("Use '/login NAME' or '/register NAME'.");
        ui_print_local("Use '/login' or '/register' to use name '%s'.", default_name);
        return 0;
    }

    if (c->auth_state != AUTH_READY)
    {
        if (out_buf[0] == '/')
        {
            ui_print_local("Command cannot be used right now. Waiting for server response.");
        }
        else
        {
            ui_print_local("Message was not sent. You are not ready yet.");
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
            ui_print_error("MESSAGE TOO LONG\n");
            return 0;
        }
        if (strncmp("/join ", out_buf, 6) == 0)
        {
            if (c->room_state != ROOM_READY)
            {
                ui_print_local("Cannot join now. Current room is not ready.");
                return 0;
            }
            errno = 0;
            char*         end;
            unsigned long room_id = strtoul(out_buf + 6, &end, 0);
            if (*end != '\0')
            {
                ui_print_error("INVALID ROOM ID\n");
                return 0;
            }
            if (end == out_buf + 6)
            {
                ui_print_error("ROOM ID IS NOT A NUMBER\n");
                return 0;
            }
            if (errno == ERANGE)
            {
                ui_print_error("ROOM ID IS OUT OF RANGE\n");
                return 0;
            }
            if (room_id < 1 || room_id > MAX_ROOMS)
            {
                ui_print_error("INVALID ROOM ID\n");
                return 0;
            }

            if ((uint32_t)room_id == c->room_id)
            {
                ui_print_local("You are already in room #%" PRIu32 "", c->room_id);
                return 0;
            }
            if (client_send_pkt_room_join_begin(epfd, c, room_id) < 0)
            {
                return -1;
            }
            c->room_state = ROOM_JOINING;
            return 0;
        }

        else if (strcmp(out_buf, "/create_room_password") == 0)
        {
            ui_print_error("USAGE: /create_room_password ROOM_ID");
            return 0;
        }

        else if (strncmp(out_buf, "/create_room_password ", 22) == 0)
        {
            if (c->room_state != ROOM_READY)
            {
                ui_print_local("Cannot create room now. Current room is not ready.");
                return 0;
            }
            errno = 0;

            char*         end     = NULL;
            unsigned long room_id = strtoul(out_buf + 22, &end, 10);

            if (end == out_buf + 22 || *end != '\0')
            {
                ui_print_error("ROOM ID IS NOT A NUMBER");
                return 0;
            }

            if (errno == ERANGE || room_id < 1 || room_id > MAX_ROOMS)
            {
                ui_print_error("ROOM ID IS OUT OF RANGE");
                return 0;
            }

            if (!awaiting_create_room_password || !pending_password_room_id)
            {
                ui_print_error("PASSWORD CREATE STATE POINTERS ARE NULL");
                return -1;
            }

            if (*awaiting_create_room_password)
            {
                ui_print_local("Already waiting for password. Type 'exit' to cancel.");
                return 0;
            }

            *awaiting_create_room_password = 1;
            *pending_password_room_id      = (uint32_t)room_id;

            ui_print_local("Please enter password for new room %" PRIu32 " or 'exit' to cancel:",
                           (uint32_t)room_id);

            return 0;
        }

        else if (strncmp(out_buf, "/create_room ", 13) == 0)
        {
            if (c->room_state != ROOM_READY)
            {
                ui_print_local("Cannot create room now. Current room is not ready.");
                return 0;
            }
            errno                 = 0;
            char*         end     = NULL;
            unsigned long room_id = strtoul(out_buf + 13, &end, 10);

            if (end == out_buf + 13 || *end != '\0')
            {
                ui_print_error("ROOM ID IS NOT A NUMBER");
                return 0;
            }

            if (errno == ERANGE || room_id < 1 || room_id > MAX_ROOMS)
            {
                ui_print_error("ROOM ID IS OUT OF RANGE");
                return 0;
            }

            return client_send_pkt_room_create(epfd, c, (uint32_t)room_id);
        }

        else if (out_buf[0] == '/')
        {
            ui_print_error("Unknown command: %s", out_buf);
            ui_print_local("Type /help to see supported commands.");
            return 0;
        }
        else
        {
            h.type            = PKT_ENC_CHAT;
            h.room_id         = c->room_id;
            RoomSession* room = find_room_session(rooms, MAX_ROOMS, c->room_id);
            if (!room)
            {
                ui_print_e2e("no room key for room#%" PRIu32 "", c->room_id);
                return 0;
            }
            if (bytes < 0 || bytes > UINT16_MAX)
            {
                fprintf(stderr, "message is too large\n");
                return -1;
            }
            if (c->room_state != ROOM_READY)
            {
                ui_print_local("Room is not ready yet.");
                return 0;
            }
            if (client_send_encrypted_chat(epfd, c, room, (uint8_t*)out_buf, (uint16_t)bytes) < 0)
            {
                fprintf(stderr, "enqueue_packet failed\n");
                return -1;
            }
            ui_print_msg(out_buf, c->name, c->room_id);
            if (set_epollout_to_client(epfd, c) < 0)
            {
                return -1;
            }
        }
    }
    return 0;
}

void print_help(Client* c, const char* default_name)
{
    if (!c || c->auth_state != AUTH_READY)
    {
        ui_print_help_logged_out(default_name);
        return;
    }

    ui_print_help_logged_in(c->room_id);
}

int send_name_command(int epfd, Client* c, uint8_t pkt_type, const char* user_name)
{
    size_t name_len = strlen(user_name);

    if (name_len == 0)
    {
        ui_print_error("EMPTY NAME\n");
        return 0;
    }

    if (name_len > MAX_NAME_LEN)
    {
        ui_print_error("NAME IS TOO LONG\n");
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
