#ifndef UI_H
#define UI_H

#include <stddef.h>
#include <stdint.h>

void ui_print_error(const char* format, ...);
void ui_print_local(const char* format, ...);
void ui_print_e2e(const char* format, ...);

void ui_print_join(const char* name, uint32_t id);
void ui_print_leave(const char* name, uint32_t id);
void ui_print_msg(const char* text, const char* name, uint32_t room_id);

void ui_print_room_create(uint32_t room_id);
void ui_print_room_change(uint32_t from_room_id, uint32_t to_room_id);
void ui_print_room_same(uint32_t room_id);
void ui_print_room_info(const char* format, ...);

void ui_clear(void);
void ui_print_welcome(const char* default_name);
void ui_print_help_logged_out(const char* default_name);
void ui_print_help_logged_in(uint32_t room_id);

void ui_input_clear(void);
void ui_input_redraw(const char* buf, size_t len);
void ui_input_redraw_masked(const char* buf, size_t len);

#endif // UI_H