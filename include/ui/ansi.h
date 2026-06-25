#ifndef ANSI_H
#define ANSI_H

#define ANSI_RESET "\x1b[0m"
#define ANSI_BOLD "\x1b[1m"
#define ANSI_DIM "\x1b[2m"

#define ANSI_GRAY "\x1b[38;5;245m"
#define ANSI_DARK_GRAY "\x1b[38;5;240m"
#define ANSI_RED "\x1b[38;5;203m"
#define ANSI_GREEN "\x1b[38;5;114m"
#define ANSI_YELLOW "\x1b[38;5;180m"
#define ANSI_BLUE "\x1b[38;5;75m"
#define ANSI_MAGENTA "\x1b[38;5;176m"
#define ANSI_CYAN "\x1b[38;5;110m"
#define ANSI_WHITE "\x1b[38;5;250m"

#define ANSI_UI_ERROR ANSI_RED
#define ANSI_UI_LOCAL ANSI_GRAY
#define ANSI_UI_E2E ANSI_MAGENTA
#define ANSI_UI_JOIN ANSI_GREEN
#define ANSI_UI_LEAVE ANSI_RED
#define ANSI_UI_ROOM ANSI_CYAN
#define ANSI_UI_ROOM_EVENT ANSI_BLUE
#define ANSI_UI_NAME ANSI_YELLOW
#define ANSI_UI_TEXT ANSI_WHITE

#define ANSI_CLEAR_LINE "\x1b[2K"
#define ANSI_CLEAR_DOWN "\x1b[J"
#define ANSI_SAVE_CURSOR "\x1b[s"
#define ANSI_RESTORE_CURSOR "\x1b[u"

#define ANSI_CLEAR_SCREEN "\x1b[2J"
#define ANSI_HOME "\x1b[H"

#define ANSI_BG_DARK "\x1b[48;5;236m"
#define ANSI_ACCENT "\x1b[38;5;110m"
#define ANSI_ACCENT2 "\x1b[38;5;176m"
#define ANSI_MUTED "\x1b[38;5;245m"
#define ANSI_BORDER "\x1b[38;5;240m"

#endif