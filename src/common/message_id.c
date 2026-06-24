#include "protocol/message_id.h"

uint32_t next_message_id(uint32_t* message_id)
{
    return ++(*message_id);
}