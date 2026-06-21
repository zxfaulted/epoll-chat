
#ifndef CONNECTION_H
#define CONNECTION_H

#include "protocol.h"
#include <netinet/in.h>

#define SERVER_ID 0
#define SERVER_PORT 5555
#define SERVER_ADDRESS "127.0.0.1"
#define MAX_EVENTS 512

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

typedef struct Connection
{
    char   in_buf[BUF_SIZE];
    size_t in_len;

    char   out_buf[BUF_SIZE];
    size_t out_len;
    size_t out_sent;

} Connection;

typedef enum ClientRoomState
{
    ROOM_NONE,

    // клиент отправил PKT_ROOM_JOIN_BEGIN
    // и ждет ответ от сервера
    // кейс с комнатой без пароля:
    // приходит PKT_ROOM_CHANGE_OK
    // сменяется состояние на ROOM_SYNCING
    //
    // кейс с комнатой с паролем:
    // если приходит PKT_ROOM_PASSWORD_INFO,
    // то переходит в ROOM_PASSWORD_UNLOCKING
    //
    // если не может войти, то обратно в ROOM_NONE
    ROOM_JOINING,

    // клиент получил PKT_ROOM_PASSWORD_INFO
    // в этом состоянии клиент
    // 1. просит пароль у пользователя
    // 2. пробует расшифровать
    // 3. если верный - получает ключ комнаты
    // 4. сохраняет ключ комнаты локально
    // 5. посылает PKT_ROOM_UNLOCK серверу
    // 6. переходит в ROOM_WAIT_JOIN_OK
    // нужно, потому что клиент "зависает",
    // ждет действие пользователя
    ROOM_PASSWORD_UNLOCKING,

    // клиент успешно расшифровал ключ комнаты
    // ждет подтверждение входа от сервера
    // PKT_ROOM_JOIN_OK
    ROOM_WAIT_JOIN_OK,

    // клиент уже принят
    // получает информацию от сервера:
    // список участников
    // key bundles участников
    // если комната без пароля -> ROOM_WAIT_ROOM_KEY
    // ждет ROOM_SYNC_DONE -> ROOM_READY
    ROOM_SYNCING,

    // ожидание ключа от лидера комнаты без пароля
    ROOM_WAIT_ROOM_KEY,

    // синхронизация завершена и есть ключ комнаты
    ROOM_READY

} ClientRoomState;

/*
 * AuthState описывает только вход и регистрацию
 * готов ли клиент писать в чат и есть ли у него room key определяет RoomState
 *
 *   AUTH_CLIENT_* - состояния, которые должен ставить только client.c
 *   AUTH_SERVER_* - состояния, которые должен ставить только server.c
 *
 * если клиент отправил пакет и ждет ответ сервера - это AUTH_CLIENT_*
 * если сервер отправил challenge и ждет следующий пакет клиента - это AUTH_SERVER_*
 *
 *
 * REGISTER:
 *
 *   client AUTH_NEW
 *     отправляет PKT_REGISTER_BEGIN
 *     -> AUTH_CLIENT_WAIT_REGISTER_CHALLENGE
 *
 *   server AUTH_NEW
 *     получает PKT_REGISTER_BEGIN
 *     отправляет PKT_REGISTER_CHALLENGE
 *     -> AUTH_SERVER_WAIT_REGISTER_RESPONSE
 *
 *   client AUTH_CLIENT_WAIT_REGISTER_CHALLENGE
 *     получает PKT_REGISTER_CHALLENGE
 *     считает ответ
 *     отправляет PKT_REGISTER_RESPONSE
 *     -> AUTH_CLIENT_WAIT_REGISTER_OK
 *
 *   server AUTH_SERVER_WAIT_REGISTER_RESPONSE
 *     получает PKT_REGISTER_RESPONSE
 *     проверяет/сохраняет нового пользователя
 *     отправляет PKT_REGISTER_OK
 *     -> AUTH_SERVER_WAIT_KEY_BUNDLE
 *
 *   client AUTH_CLIENT_WAIT_REGISTER_OK
 *     получает PKT_REGISTER_OK
 *     отправляет PKT_ENC_KEY_BUNDLE
 *     -> AUTH_CLIENT_WAIT_KEY_BUNDLE_OK
 *
 *
 * LOGIN:
 *
 *   client AUTH_NEW
 *     отправляет PKT_AUTH_BEGIN
 *     (ранее PKT_NAME)
 *     -> AUTH_CLIENT_WAIT_AUTH_CHALLENGE
 *
 *   server AUTH_NEW
 *     получает PKT_AUTH_BEGIN
 *     отправляет PKT_AUTH_CHALLENGE
 *     -> AUTH_SERVER_WAIT_AUTH_RESPONSE
 *
 *   client AUTH_CLIENT_WAIT_AUTH_CHALLENGE
 *     получает PKT_AUTH_CHALLENGE
 *     считает ответ
 *     отправляет PKT_AUTH_RESPONSE
 *     -> AUTH_CLIENT_WAIT_AUTH_OK
 *
 *   server AUTH_SERVER_WAIT_AUTH_RESPONSE
 *     получает PKT_AUTH_RESPONSE
 *     проверяет ответ
 *     отправляет PKT_AUTH_OK
 *     -> AUTH_SERVER_WAIT_KEY_BUNDLE
 *
 *   client AUTH_CLIENT_WAIT_AUTH_OK
 *     получает PKT_AUTH_OK
 *     отправляет PKT_ENC_KEY_BUNDLE
 *     -> AUTH_CLIENT_WAIT_KEY_BUNDLE_OK
 *
 *
 * KEY BUNDLE:
 *
 *   server AUTH_SERVER_WAIT_KEY_BUNDLE
 *     получает PKT_ENC_KEY_BUNDLE
 *     сохраняет публичный E2E bundle клиента
 *     отправляет PKT_KEY_BUNDLE_OK
 *     -> AUTH_READY
 *
 *   client AUTH_CLIENT_WAIT_KEY_BUNDLE_OK
 *     получает PKT_KEY_BUNDLE_OK
 *     -> AUTH_READY
 *
 *
 * ошибка в любом промежуточном состоянии:
 *   PKT_ERROR / невалидный пакет / невалидная проверка
 *   -> AUTH_NEW или закрытие соединения
 *
 * AUTH_READY значит только:
 *   пользователь принят
 *   key bundle принят сервером
 *   можно начинать room sync
 *
 * AUTH_READY НЕ значит:
 *   уже есть ключ комнаты
 *   уже завершен room sync
 *   уже можно слать PKT_ENC_CHAT
 */
typedef enum AuthState
{
    AUTH_NEW,

    AUTH_CLIENT_WAIT_REGISTER_CHALLENGE,
    AUTH_CLIENT_WAIT_REGISTER_OK,

    AUTH_CLIENT_WAIT_AUTH_CHALLENGE,
    AUTH_CLIENT_WAIT_AUTH_OK,

    AUTH_CLIENT_WAIT_KEY_BUNDLE_OK,

    AUTH_SERVER_WAIT_REGISTER_RESPONSE,
    AUTH_SERVER_WAIT_AUTH_RESPONSE,
    AUTH_SERVER_WAIT_KEY_BUNDLE,

    AUTH_READY
} AuthState;

typedef struct Client
{
    EpollItem ei;
    uint32_t  id;
    char      name[MAX_NAME_LEN + 1];

    uint32_t   room_id;
    Connection conn;

    AuthState       auth_state;
    ClientRoomState room_state;

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

#endif