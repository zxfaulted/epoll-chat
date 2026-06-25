#include "server/server_rooms.h"

#include "protocol/wire.h"

#include <stdio.h>
#include <string.h>

void init_server_rooms(ServerRoom* room, uint16_t rooms_count)
{
    memset(room, 0, sizeof(*room) * rooms_count);
}

uint32_t server_room_has_owner(ServerRoom* rooms, uint32_t rooms_count, uint32_t room_id)
{
    for (size_t i = 1; i < rooms_count; ++i)
    {
        if (rooms[i].used && rooms[i].room_id == room_id)
        {
            return rooms[i].owner_id;
        }
    }
    return 0;
}

uint32_t server_room_find_room_id_by_owner_id(ServerRoom* rooms, uint32_t rooms_count,
                                              uint32_t client_id)
{
    for (size_t i = 1; i < rooms_count; ++i)
    {
        if (rooms[i].used && rooms[i].owner_id == client_id)
        {
            return rooms[i].room_id;
        }
    }
    return 0;
}

uint32_t server_room_is_owner(ServerRoom* rooms, uint32_t rooms_count, uint32_t room_id,
                              uint32_t client_id)
{
    for (size_t i = 1; i < rooms_count; ++i)
    {
        if (rooms[i].used && rooms[i].room_id == room_id && rooms[i].owner_id == client_id)
        {
            return room_id;
        }
    }
    return 0;
}

uint32_t server_room_is_owner_of_any(ServerRoom* rooms, uint32_t rooms_count, uint32_t client_id)
{
    for (size_t i = 1; i < rooms_count; ++i)
    {
        if (rooms[i].used && rooms[i].owner_id == client_id)
        {
            return rooms[i].room_id;
        }
    }
    return 0;
}

ServerRoom* server_room_find_by_id(ServerRoom* rooms, uint32_t rooms_count, uint32_t room_id)
{
    for (size_t i = 0; i < rooms_count; i++)
    {
        if (rooms[i].used && rooms[i].room_id == room_id)
        {
            return &rooms[i];
        }
    }
    return NULL;
}

int build_pkt_room_create_payload(uint8_t* out_msg, uint16_t* out_msg_len, uint32_t room_id)
{
    if (!out_msg || !out_msg_len)
    {
        return -1;
    }

    put_u32_be(out_msg, room_id);
    *out_msg_len = ROOM_ID_LEN;

    return 0;
}

int parse_pkt_room_create_payload(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id)
{
    if (!msg || !out_room_id)
    {
        return -1;
    }
    if (msg_len != ROOM_ID_LEN)
    {
        return -1;
    }
    *out_room_id = get_u32_be(msg);
    return 0;
}

int server_room_create(ServerRoom* rooms, uint16_t rooms_count, uint32_t room_id,
                       uint32_t potential_owner_id)
{
    if (server_room_has_owner(rooms, rooms_count, room_id))
    {
        fprintf(stderr, "room has already an owner\n");
        return -1;
    }
    for (size_t i = 1; i < rooms_count; ++i)
    {
        if (!rooms[i].used)
        {
            memset(&rooms[i], 0, sizeof(rooms[i]));
            rooms[i].room_id      = room_id;
            rooms[i].owner_id     = potential_owner_id;
            rooms[i].used         = 1;
            rooms[i].has_password = 0;
            return i;
        }
    }
    return -2;
}

int server_room_create_password(ServerRoom* rooms, uint16_t rooms_count, uint32_t room_id,
                                uint32_t potential_owner_id, RoomPasswordInfo* rpi)
{
    if (!rooms || !rpi)
    {
        return -1;
    }
    if (server_room_has_owner(rooms, rooms_count, room_id))
    {
        fprintf(stderr, "room has already an owner\n");
        return -1;
    }
    for (size_t i = 1; i < rooms_count; ++i)
    {
        if (!rooms[i].used)
        {
            memset(&rooms[i], 0, sizeof(rooms[i]));
            rooms[i].room_id  = room_id;
            rooms[i].owner_id = potential_owner_id;
            rooms[i].used     = 1;

            memcpy(rooms[i].rpi.encrypted_room_key, rpi->encrypted_room_key,
                   ENCRYPTED_ROOM_KEY_LEN);
            memcpy(rooms[i].rpi.nonce, rpi->nonce, ROOM_NONCE_LEN);
            memcpy(rooms[i].rpi.salt, rpi->salt, ROOM_SALT_LEN);
            memcpy(rooms[i].rpi.tag, rpi->tag, ROOM_TAG_LEN);
            memcpy(rooms[i].rpi.verifier, rpi->verifier, ROOM_PASSWORD_VERIFIER_LEN);
            rooms[i].rpi.epoch    = rpi->epoch;
            rooms[i].has_password = 1;
            return i;
        }
    }
    // все комнаты заняты
    return -2;
}

int server_room_update_metadata(ServerRoom* room, RoomPasswordInfo* rpi)
{
    if (!room || !rpi)
    {
        return -1;
    }

    memcpy(room->rpi.encrypted_room_key, rpi->encrypted_room_key, ENCRYPTED_ROOM_KEY_LEN);
    room->rpi.epoch = rpi->epoch;
    memcpy(room->rpi.nonce, rpi->nonce, ROOM_NONCE_LEN);
    memcpy(room->rpi.salt, rpi->salt, ROOM_SALT_LEN);
    memcpy(room->rpi.tag, rpi->tag, ROOM_TAG_LEN);
    memcpy(room->rpi.verifier, rpi->verifier, ROOM_PASSWORD_VERIFIER_LEN);

    return 0;
}

void server_room_delete_by_owner(ServerRoom* rooms, uint32_t rooms_count, uint32_t owner_id)
{
    if (!rooms || owner_id == 0)
    {
        return;
    }

    for (uint32_t i = 1; i < rooms_count; ++i)
    {
        if (rooms[i].used && rooms[i].owner_id == owner_id)
        {
            memset(&rooms[i], 0, sizeof(rooms[i]));
        }
    }
}

void server_room_delete_by_id(ServerRoom* rooms, uint32_t rooms_count, uint32_t room_id)
{
    if (!rooms)
    {
        return;
    }

    for (uint32_t i = 0; i < rooms_count; ++i)
    {
        if (!rooms[i].used)
        {
            continue;
        }

        if (rooms[i].room_id != room_id)
        {
            continue;
        }

        memset(&rooms[i], 0, sizeof(rooms[i]));
        return;
    }
}