#ifndef SERVER_ROOM_H
#define SERVER_ROOM_H

#include "e2e_protocol.h"
#include "room_password.h"

typedef struct ServerRoom
{
    uint32_t room_id;
    uint32_t owner_id;
    uint32_t leader_id;

    int used;

    int has_password;

    RoomPasswordInfo rpi;

} ServerRoom;

void     init_server_rooms(ServerRoom* room, uint16_t rooms_count);
uint32_t server_room_has_owner(ServerRoom* room, uint32_t rooms_count, uint32_t room_id);
uint32_t server_room_is_owner(ServerRoom* rooms, uint32_t rooms_count, uint32_t room_id,
                              uint32_t client_id);
int      build_pkt_room_create_payload(uint8_t* out_msg, uint16_t* out_msg_len, uint32_t room_id);
int      parse_pkt_room_create_payload(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id);
int      server_room_create(ServerRoom* rooms, uint16_t rooms_count, uint32_t room_id,
                            uint32_t potential_owner_id);
int      server_room_create_password(ServerRoom* rooms, uint16_t rooms_count, uint32_t room_id,
                                     uint32_t potential_owner_id, RoomPasswordInfo* rpi);
ServerRoom* server_room_find_by_id(ServerRoom* rooms, uint32_t rooms_count, uint32_t room_id);
uint32_t server_room_is_owner_of_any(ServerRoom* rooms, uint32_t rooms_count, uint32_t client_id);
int      server_room_update_metadata(ServerRoom* room, RoomPasswordInfo* rpi);
#endif // SERVER_ROOM_H