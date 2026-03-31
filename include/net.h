
#ifndef NET_H
#define NET_H
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#define SERVER_ID 0
#define SERVER_PORT 5555
#define SERVER_ADDRESS "127.0.0.1"
#define MAX_EVENTS 512
#define MAX_CLIENTS 1024

#define MAX_NAME_LEN 32
#define BUF_SIZE 8192

#define FRAME_LEN_SIZE 4
#define VERSION_SIZE 1
#define TYPE_SIZE 1
#define FLAGS_SIZE 2
#define SENDER_ID_SIZE 4
#define ROOM_ID_SIZE 4
#define TIMESTAMP_SIZE 8
#define MESSAGE_ID_SIZE 4

#define OUT_CAP (PAYLOAD_SIZE + 1)

#define HEADER_SIZE                                                                                \
    (VERSION_SIZE + TYPE_SIZE + FLAGS_SIZE + SENDER_ID_SIZE + ROOM_ID_SIZE + TIMESTAMP_SIZE +      \
     MESSAGE_ID_SIZE)

#define MAX_PAYLOAD_SIZE 1024
#define PAYLOAD_SIZE MAX_PAYLOAD_SIZE
#define PAYLOAD_ID_AND_NAME_SIZE (SENDER_ID_SIZE + MAX_NAME_LEN)

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
    STATE_READY
} ClientState;

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

    Connection         conn;
    ClientState        state;
    struct sockaddr_in sa;

} Client;

typedef struct Server
{
    EpollItem          ei;
    struct sockaddr_in sa;
} Server;

typedef enum
{
    PKT_CHAT = 0,
    PKT_REGISTER_OK,
    PKT_JOIN,
    PKT_LEAVE,
    PKT_NAME,
    PKT_ERR
} PacketType;

// [4 frame_len]
// [1 version]
// [1 type]
// [2 flags]
// [4 sender_id]
// [4 room_id]
// [8 timestamp]
// [4 msg_id]
// [payload]
typedef struct Header
{
    uint8_t  version;
    uint8_t  type;
    uint16_t flags;
    uint32_t sender_id;
    uint32_t room_id;
    uint64_t timestamp;
    uint32_t message_id;
} Header;

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

int  send_server_error(int epfd, Client* c, const char msg[], uint32_t* message_id);
int  set_epollout_to_client(int epfd, Client* c);
int  unset_epollout_to_client(int epfd, Client* c);
int  parse_client_id_and_name(const uint8_t* msg, uint32_t msg_len, uint32_t* id, char name[]);
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
void        broadcast_user_event(int epfd, Client* skip, Client* clients[], int* clients_count,
                                 PacketType type, uint32_t* message_id);
int send_server_ready_users(Client* c, Client* clients[], int clients_count, uint32_t* message_id);
const char* packet_type_str(PacketType type);

int payload_to_str(const uint8_t payload[], size_t len, char out[], size_t out_cap);

// только для register_ok|join|leave пакетов
// 0 успех
// -1 ошибка
int send_server_user_event(Client* c, PacketType type, const char* name, uint32_t user_id,
                           uint32_t* message_id);

uint32_t next_message_id(uint32_t* message_id);

#endif