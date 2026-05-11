
#ifndef NET_H
#define NET_H
#include "protocol.h"
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#define SERVER_ID 0
#define SERVER_PORT 5555
#define SERVER_ADDRESS "127.0.0.1"
#define MAX_EVENTS 512
#define MAX_CLIENTS 1024
#define MAX_ROOMS 128

#define OUT_CAP (PAYLOAD_SIZE + 1)

// [4 frame_len]
// [1 version]
// [1 type]
// [2 flags]
// [4 sender_id]
// [4 room_id]
// [8 timestamp]
// [4 msg_id]

typedef enum
{
    CLIENT_ITEM,
    SERVER_ITEM,
    STDIN_ITEM
} Item;

typedef struct EpollItem
{
    Item item;
    int  fd;
} EpollItem;

typedef enum
{
    STATE_WAIT_NAME,
    STATE_WAIT_AUTH_CHALLENGE,
    STATE_WAIT_AUTH_RESPONSE,

    STATE_WAIT_REGISTER_CHALLENGE,
    STATE_WAIT_REGISTER_COMMIT,

    STATE_WAIT_KEY_BUNDLE,
    STATE_WAIT_REGISTER_OK,
    STATE_WAIT_ROOM_KEY,
    STATE_READY
} ClientState;

typedef struct RoomPeerRecvState
{
    uint32_t peer_id;
    uint64_t seq;
    int      used;

} RoomPeerRecvState;

typedef struct RoomSession
{
    uint32_t room_id;

    uint64_t epoch;
    uint8_t  room_key[ROOM_KEY_LEN];

    uint64_t send_seq;

    RoomPeerRecvState recv[MAX_CLIENTS];

    int used;
} RoomSession;

typedef struct PeerWrapSession
{
    uint32_t peer_id;

    uint8_t  fingerprint[64];
    uint16_t fingerprint_len;

    uint8_t wrapping_key[32];

    int used;
} PeerWrapSession;

typedef struct Connection
{
    char   in_buf[BUF_SIZE];
    size_t in_len;

    char   out_buf[BUF_SIZE];
    size_t out_len;
    size_t out_sent;

} Connection;

typedef struct Client
{
    EpollItem ei;
    uint32_t  id;
    char      name[MAX_NAME_LEN + 1];

    uint32_t           room_id;
    Connection         conn;
    ClientState        state;
    struct sockaddr_in sa;

    uint8_t* raw_kb;
    uint16_t raw_kb_len;
    int      has_kb;

    int     has_name;
    uint8_t challenge[32];
    int     auth_pending;
    int     authenticated;

    int close_after_flush;
} Client;

typedef struct Server
{
    EpollItem          ei;
    struct sockaddr_in sa;
} Server;

// [4 frame_len]
// [24 Header]
// [32 EncChatHeader] входит в AAD
// [ciphertext] шифруется
// [tag]
// Кузнечик + MGM = AEAD
typedef struct
{
    // версия протокола
    uint8_t version;
    // алгоритм шифрования
    uint8_t suite;
    // резерв для выравнивания структуры
    uint16_t reserved;
    // версия ключа
    uint64_t room_epoch;
    // счетчик сообщения
    uint64_t seq;
    uint8_t  nonce[16];

} EncChatHeader;

typedef enum
{
    PKT_OK,
    PKT_BAD_VERSION,
    PKT_BAD_TYPE,
    PKT_BAD_FLAGS,
    PKT_BAD_SENDER_ID,
    PKT_BAD_ROOM_ID,
    PKT_BAD_TIMESTAMP,
    PKT_BAD_MESSAGE_ID,
    PKT_BAD_PAYLOAD_SIZE
} PacketState;

// хранилище пользователей текущей комнаты
typedef struct
{
    uint32_t id;
    char     name[MAX_NAME_LEN + 1];
    int      used;
} UserEntry;

typedef struct PendingReg
{
    char     name[MAX_NAME_LEN + 1];
    uint32_t id;
    uint8_t  challenge[32];
    uint64_t expires_at;
    int      used;
} PendingReg;

int set_nonblocking(int fd);

// [4 len][header][payload]
int enqueue_packet(Client* c, Header* header, const uint8_t* msg, uint32_t len);

// recv в in_buf
// возвращает
// bytes > 0 при успехе
// 0 пока нет данных
// -1 соединение закрыто
// -2 ошибка
int recv_into_inbuf(Client* c);

// pop пакета из in_buf в dst и dst_len
// dst должен быть размером хотя бы PAYLOAD_SIZE + 1
// 1 при успешном извлечении
// 0 в буфере нет полного ответа
// -2 ошибка протокола
int try_pop_packet(Client* c, Header* header, uint8_t* dst, uint32_t* dst_len);

// отправить все возможное из out_buf
int flush_send(Client* c);

// 0 успех
// -1 ошибка
int add_new_client(int epfd, int server_fd, Client* clients[], int* clients_count, uint32_t* id);

void broadcast_message(int epfd, Client* c, Header* h, Client* clients[], int* clients_count,
                       const uint8_t msg[], uint32_t len, uint32_t* message_id);

int send_server_error(int epfd, Client* c, const char msg[], uint32_t* message_id);
int set_epollout_to_client(int epfd, Client* c);
int unset_epollout_to_client(int epfd, Client* c);
int parse_client_id_and_name(const uint8_t* msg, uint32_t msg_len, uint32_t* client_id,
                             char name[]);
int parse_client_register_ok(const uint8_t* msg, uint32_t msg_len, uint32_t* client_id,
                             uint32_t* room_id, char name[]);

void reject_packet(int epfd, Client* c, int cur_fd, Client* clients[], int* clients_count,
                   const char* reason, uint32_t* message_id);

const char* packet_state_str(PacketState st);

// 0 успех
// -1 ошибка
int         set_client_name(Client* c, const char* msg, size_t msg_len);
PacketState validate_packet_name(uint32_t msg_len, Header* h);
PacketState validate_packet_chat(uint32_t msg_len, Header* h);
int         is_name_taken(Client* clients[], int clients_count, const char* name, size_t name_len);
int         disconnect_client(int epfd, Client* c, Client* clients[], int* clients_count,
                              uint32_t* message_id);
void        broadcast_user_event(int epfd, Client* skip, uint32_t room_id, Client* clients[],
                                 int* clients_count, PacketType type, uint32_t* message_id);
int send_server_ready_users(Client* c, uint32_t room_id, Client* clients[], int clients_count,
                            uint32_t* message_id);
const char* packet_type_str(PacketType type);

int payload_to_str(const uint8_t payload[], size_t len, char out[], size_t out_cap);

// только для register_ok|jo    in|leave пакетов
// 0 успех
// -1 ошибка
int send_server_user_event(Client* c, uint32_t room_id, PacketType type, const char* name,
                           uint32_t user_id, uint32_t* message_id);

uint32_t next_message_id(uint32_t* message_id);

PacketState validate_packet_room_change(uint32_t msg_len, Header* h);
int         send_server_register_ok(Client* c, uint32_t room_id, const char* name, uint32_t user_id,
                                    uint32_t* message_id);
int         add_user_entry(UserEntry* ue, const char* name, uint32_t id);
int         remove_user_entry_by_id(UserEntry* ue, uint32_t id);
const char* find_user_name_by_id(const UserEntry* ue, uint32_t id);
int         send_kb(Client* c, uint8_t* kb, uint16_t kb_len, uint32_t owner_id, uint32_t room_id,
                    uint32_t* message_id);
int send_server_ready_key_bundles(int epfd, Client* c, Client* clients[], int* clients_count,
                                  uint32_t* message_id);
int send_server_new_key_bundle(int epfd, Client* c, Client* clients[], int clients_count,
                               uint32_t* message_id);
int forward_room_key_packet(int epfd, Client* clients[], int clients_count, Client* from, Header* h,
                            uint8_t* msg, uint32_t msg_len, uint32_t* message_id);
int check_recv_seq(RoomSession* room, uint64_t peer_id, uint64_t recv_seq);
int server_verify_challenge(Client* c, uint8_t* msg, uint16_t msg_len);
int add_pending_registration(PendingReg* pr, const char* name, uint8_t* challenge,
                             uint32_t client_id);
void remove_pending_registration(PendingReg* pr, const char* name, uint32_t client_id);
int  find_in_pending_registrations(PendingReg* pr, const char* name, uint32_t client_id);
int  client_send_pkt_register_commit(int epfd, Client* c, uint8_t* identity_pub_der,
                                     uint16_t identity_pub_der_len, uint8_t* sig, uint16_t siglen);
int  server_send_registration_challenge(int epfd, Client* c, uint32_t temp_client_id,
                                        const uint8_t challenge[CHALLENGE_LEN],
                                        uint32_t*     message_id);
#endif