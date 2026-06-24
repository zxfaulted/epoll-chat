#include "auth/user_table.h"
#include "e2e/e2e_protocol.h"

#include <string.h>

// 0 успех
// -1 ошибка
int add_user_entry(UserEntry* ue, const char* name, uint32_t id)
{
    if (!ue || !name)
    {
        return -1;
    }
    int empty_slot = -1;
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (ue[i].used == 1)
        {
            if (ue[i].id == id)
            {
                return -1;
            }
            continue;
        }
        if (empty_slot == -1)
        {
            empty_slot = i;
        }
    }
    if (empty_slot != -1)
    {
        ue[empty_slot].id = id;
        strncpy(ue[empty_slot].name, name, sizeof(ue[empty_slot].name) - 1);
        ue[empty_slot].name[sizeof(ue[empty_slot].name) - 1] = '\0';
        ue[empty_slot].used                                  = 1;
        return 0;
    }
    return -1;
}

int remove_user_entry_by_id(UserEntry* ue, uint32_t id)
{
    if (!ue)
    {
        return -1;
    }
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (ue[i].used == 0 || ue[i].id != id)
        {
            continue;
        }
        ue[i].id = 0;
        memset(ue[i].name, 0, sizeof(ue[i].name));
        ue[i].used = 0;
        return 0;
    }
    return -1;
}

const char* find_user_name_by_id(const UserEntry* ue, uint32_t id)
{
    if (!ue)
    {
        return NULL;
    }
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (ue[i].used == 0 || ue[i].id != id)
        {
            continue;
        }
        return ue[i].name;
    }
    return NULL;
}

int room_has_peers(const UserEntry* ue)
{
    if (!ue)
    {
        return 0;
    }

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (ue[i].used)
        {
            return 1;
        }
    }

    return 0;
}

int user_entry_exists(const UserEntry* ue, uint32_t id)
{
    if (!ue)
    {
        return 0;
    }

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (ue[i].used && ue[i].id == id)
        {
            return 1;
        }
    }

    return 0;
}