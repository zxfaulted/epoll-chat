
#ifndef NET_H
#define NET_H
#include "crypto.h"
#include "e2e_message.h"
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#define OUT_CAP (PAYLOAD_SIZE + 1)

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

// 0 успех
// -1 ошибка
int add_new_client(int epfd, int server_fd, Client* clients[], int* clients_count, uint32_t* id);

void broadcast_message(int epfd, Client* c, Header* h, Client* clients[], int* clients_count,
                       const uint8_t msg[], uint32_t len, uint32_t* message_id);

int send_server_error(int epfd, Client* c, const char msg[], uint32_t* message_id);
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

int  client_send_pkt_register_commit(int epfd, Client* c, uint8_t* identity_pub_der,
                                     uint16_t identity_pub_der_len, uint8_t* sig, uint16_t siglen);
int  handle_input(int epfd, Client* c, RoomSession* rooms, GeneratedKeys* gk, char* out_buf,
                  ssize_t bytes, const char* default_name, int* registration_in_progress,
                  int* generated_keys_for_registration);
void print_help(Client* c);
int  send_name_command(int epfd, Client* c, uint8_t pkt_type, const char* user_name);
RoomSession* find_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id);

int client_send_pkt_enc_chat(int epfd, Client* c, RoomSession* room, uint8_t* msg,
                             uint16_t msg_len);
int client_response_challenge(int epfd, Client* c, uint8_t* msg, uint16_t msg_len,
                              EVP_PKEY* private_key);
int send_room_key_to_peer(Client* c, uint32_t peer_id, uint8_t* wrapping_key, RoomSession* room);
Client* find_client(Client* clients[], int clients_count, uint32_t client_id);

#endif