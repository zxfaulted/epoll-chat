#include "ui/ui.h"

#include "ui/ansi.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

void ui_print_error(const char* format, ...)
{
    printf(ANSI_UI_ERROR "%7s" ANSI_RESET " ", "error");

    va_list args;
    va_start(args, format);

    vprintf(format, args);

    va_end(args);

    printf("\n");
    fflush(stdout);
}

void ui_print_local(const char* format, ...)
{
    printf(ANSI_UI_LOCAL "%7s" ANSI_RESET " ", "local");

    va_list args;
    va_start(args, format);

    vprintf(format, args);

    va_end(args);

    printf("\n");
    fflush(stdout);
}

void ui_print_e2e(const char* format, ...)
{
    printf(ANSI_UI_E2E "%7s" ANSI_RESET " ", "e2e");

    va_list args;
    va_start(args, format);

    vprintf(format, args);

    va_end(args);

    printf("\n");
    fflush(stdout);
}

void ui_print_join(const char* name, uint32_t id)
{
    printf(ANSI_UI_JOIN "%7s" ANSI_RESET " %s#%" PRIu32 "\n", "join", name, id);
    fflush(stdout);
}

void ui_print_msg(const char* text, const char* name, uint32_t room_id)
{
    printf(ANSI_UI_ROOM "[room #%" PRIu32 "]" ANSI_RESET " " ANSI_UI_NAME "%s:" ANSI_RESET
                        " " ANSI_UI_TEXT "%s" ANSI_RESET "\n",
           room_id, name, text);
    fflush(stdout);
}

void ui_clear(void)
{
    printf(ANSI_CLEAR_SCREEN ANSI_HOME);
    fflush(stdout);
}

void ui_print_welcome(const char* default_name)
{
    ui_clear();

    printf("\n");
    printf(ANSI_BORDER "╭────────────────────────────────────────╮\n" ANSI_RESET);
    printf(ANSI_BORDER "│" ANSI_RESET ANSI_BOLD ANSI_ACCENT
                       "              secure chat               " ANSI_RESET ANSI_BORDER
                       "│\n" ANSI_RESET);
    printf(ANSI_BORDER "├────────────────────────────────────────┤\n" ANSI_RESET);

    printf(ANSI_BORDER "│" ANSI_RESET " default name: " ANSI_UI_NAME "%-25s" ANSI_RESET ANSI_BORDER
                       "│\n" ANSI_RESET,
           default_name);

    printf(ANSI_BORDER "│                                        │\n" ANSI_RESET);

    printf(ANSI_BORDER "│" ANSI_RESET " " ANSI_ACCENT "1" ANSI_RESET
                       "  login as default user               " ANSI_BORDER "│\n" ANSI_RESET);

    printf(ANSI_BORDER "│" ANSI_RESET " " ANSI_ACCENT "2" ANSI_RESET
                       "  register default user               " ANSI_BORDER "│\n" ANSI_RESET);

    printf(ANSI_BORDER "│" ANSI_RESET " " ANSI_ACCENT "3" ANSI_RESET
                       "  show commands                       " ANSI_BORDER "│\n" ANSI_RESET);

    printf(ANSI_BORDER "│                                        │\n" ANSI_RESET);
    printf(ANSI_BORDER "│" ANSI_RESET ANSI_MUTED
                       " or type: /login NAME, /register NAME   " ANSI_RESET ANSI_BORDER
                       "│\n" ANSI_RESET);

    printf(ANSI_BORDER "╰────────────────────────────────────────╯\n" ANSI_RESET);
    printf("\n");
    fflush(stdout);
}

void ui_print_help_logged_out(const char* default_name)
{
    printf("\n");
    printf(ANSI_BORDER "╭─ commands before login ────────────────╮\n" ANSI_RESET);
    printf(ANSI_BORDER "│" ANSI_RESET " /login                 login as " ANSI_UI_NAME
                       "%-8s" ANSI_RESET ANSI_BORDER "│\n" ANSI_RESET,
           default_name);

    printf(ANSI_BORDER "│" ANSI_RESET " /register              register " ANSI_UI_NAME
                       "%-8s" ANSI_RESET ANSI_BORDER "│\n" ANSI_RESET,
           default_name);

    printf(ANSI_BORDER "│" ANSI_RESET " /login NAME            login as NAME      " ANSI_BORDER
                       "│\n" ANSI_RESET);

    printf(ANSI_BORDER "│" ANSI_RESET " /register NAME         register NAME      " ANSI_BORDER
                       "│\n" ANSI_RESET);

    printf(ANSI_BORDER "│" ANSI_RESET " /help                  show this menu    " ANSI_BORDER
                       "│\n" ANSI_RESET);

    printf(ANSI_BORDER "╰────────────────────────────────────────╯\n" ANSI_RESET);
    fflush(stdout);
}

void ui_print_help_logged_in(uint32_t room_id)
{
    printf("\n");
    printf(ANSI_BORDER "╭─ chat commands ────────────────────────╮\n" ANSI_RESET);

    printf(ANSI_BORDER "│" ANSI_RESET " current room: " ANSI_UI_ROOM
                       "#%-23" PRIu32 ANSI_RESET ANSI_BORDER "│\n" ANSI_RESET,
           room_id);

    printf(ANSI_BORDER "│                                         │\n" ANSI_RESET);

    printf(ANSI_BORDER "│" ANSI_RESET " /join ROOM_ID                         " ANSI_BORDER
                       "│\n" ANSI_RESET);

    printf(ANSI_BORDER "│" ANSI_RESET " /create_room ROOM_ID                  " ANSI_BORDER
                       "│\n" ANSI_RESET);

    printf(ANSI_BORDER "│" ANSI_RESET " /create_room_password ROOM_ID        " ANSI_BORDER
                       "│\n" ANSI_RESET);

    printf(ANSI_BORDER "│" ANSI_RESET " /help                                 " ANSI_BORDER
                       "│\n" ANSI_RESET);

    printf(ANSI_BORDER "│                                        │\n" ANSI_RESET);
    printf(ANSI_BORDER "│" ANSI_RESET ANSI_MUTED
                       " plain text sends message to room      " ANSI_RESET ANSI_BORDER
                       "│\n" ANSI_RESET);

    printf(ANSI_BORDER "╰────────────────────────────────────────╯\n" ANSI_RESET);
    fflush(stdout);
}

void ui_input_clear(void)
{
    printf("\r" ANSI_CLEAR_LINE);
    fflush(stdout);
}

void ui_input_redraw(const char* buf, size_t len)
{
    printf("\r" ANSI_CLEAR_LINE ANSI_GRAY "> " ANSI_RESET);

    if (buf && len > 0)
    {
        fwrite(buf, 1, len, stdout);
    }

    fflush(stdout);
}

void ui_input_redraw_masked(const char* buf, size_t len)
{
    printf("\r" ANSI_CLEAR_LINE ANSI_GRAY "> " ANSI_RESET);

    if (buf && len > 0)
    {
        for (size_t i = 0; i < len; ++i)
        {
            putchar('*');
        }
    }

    fflush(stdout);
}

void ui_print_leave(const char* name, uint32_t id)
{
    printf(ANSI_UI_LEAVE "%7s" ANSI_RESET " %s#%" PRIu32 "\n", "leave", name, id);
    fflush(stdout);
}

void ui_print_room_create(uint32_t room_id)
{
    printf(ANSI_UI_ROOM_EVENT "%7s" ANSI_RESET " created room " ANSI_UI_ROOM
                              "#%" PRIu32 ANSI_RESET ANSI_MUTED "  use /join %" PRIu32
                              " to enter" ANSI_RESET "\n",
           "room", room_id, room_id);

    fflush(stdout);
}

void ui_print_room_change(uint32_t from_room_id, uint32_t to_room_id)
{
    printf(ANSI_UI_ROOM_EVENT "%7s" ANSI_RESET " changed room " ANSI_UI_ROOM
                              "#%" PRIu32 ANSI_RESET ANSI_MUTED " -> " ANSI_RESET ANSI_UI_ROOM
                              "#%" PRIu32 ANSI_RESET "\n",
           "room", from_room_id, to_room_id);

    fflush(stdout);
}

void ui_print_room_same(uint32_t room_id)
{
    printf(ANSI_UI_ROOM_EVENT "%7s" ANSI_RESET " already in room " ANSI_UI_ROOM
                              "#%" PRIu32 ANSI_RESET "\n",
           "room", room_id);

    fflush(stdout);
}

void ui_print_room_info(const char* format, ...)
{
    printf(ANSI_UI_ROOM_EVENT "%7s" ANSI_RESET " ", "room");

    va_list args;
    va_start(args, format);

    vprintf(format, args);

    va_end(args);

    printf("\n");
    fflush(stdout);
}