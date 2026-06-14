
#ifndef USER_TABLE_H
#define USER_TABLE_H

#include "connection.h"
#include "types.h"
#include <stdint.h>

// хранилище пользователей текущей комнаты
typedef struct
{
    uint32_t id;
    char     name[MAX_NAME_LEN + 1];
    int      used;
} UserEntry;

int         add_user_entry(UserEntry* ue, const char* name, uint32_t id);
int         remove_user_entry_by_id(UserEntry* ue, uint32_t id);
const char* find_user_name_by_id(const UserEntry* ue, uint32_t id);
int         room_has_peers(const UserEntry* ue);
int         user_entry_exists(const UserEntry* ue, uint32_t id);
int         am_room_leader(const Client* c, const UserEntry* ue);
uint32_t    room_leader_id(const Client* c, const UserEntry* ue);

#endif