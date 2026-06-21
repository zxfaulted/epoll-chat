#include "state_rules.h"

int server_packet_allow(Client* c, PacketType type, AuthState auth)
{
    if (!c)
    {
        return 0;
    }
    switch (auth)
    {
        case AUTH_NEW:
        {
            return type == PKT_AUTH_BEGIN || type == PKT_REGISTER_BEGIN;
        }
        case AUTH_SERVER_WAIT_REGISTER_RESPONSE:
        {
            return type == PKT_AUTH_RESPONSE;
        }
        case AUTH_SERVER_WAIT_AUTH_RESPONSE:
        {
            return type == PKT_AUTH_RESPONSE;
        }
        case AUTH_SERVER_WAIT_KEY_BUNDLE:
        {
            return type == PKT_ENC_KEY_BUNDLE;
        }
        case AUTH_READY:
        {
            switch (type)
            {
                case PKT_CHAT:
                case PKT_ENC_CHAT:
                case PKT_ENC_ROOM_KEY:
                case PKT_LEAVE:
                {
                    return c->room_id != 0;
                }
                case PKT_ROOM_CREATE:
                case PKT_ROOM_CREATE_PASSWORD:
                case PKT_ROOM_JOIN_BEGIN:
                case PKT_ROOM_UNLOCK:
                {
                    return 1;
                }
                default:
                    return 0;
            }
        }
        default:
            return 0;
    }
    return 0;
}