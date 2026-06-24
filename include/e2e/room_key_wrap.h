#ifndef E2E_WRAP_ROOM_KEY
#define E2E_WRAP_ROOM_KEY

#include "e2e/client_room_session.h"
#include "transport/connection.h"

int e2e_wrap_room_key(uint32_t client_id, uint32_t peer_id, uint32_t room_id, uint64_t epoch,
                      uint8_t* wrapping_key, uint8_t* room_key, uint8_t* out_cipher,
                      uint8_t* out_tag, uint8_t* out_nonce);

#endif // E2E_WRAP_ROOM_KEY