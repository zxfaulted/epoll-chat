#include "transport/packet_io.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define ntohll(x) htonll(x)

static uint64_t htonll(uint64_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint32_t low    = htonl((uint32_t)(x & 0xFFFFFFFFULL));
    uint32_t high   = htonl((uint32_t)(x >> 32));
    uint64_t result = ((uint64_t)low << 32) | high;
    return result;
#else
    return x;
#endif
}

// кладет пакет сообщения msg и длины len в out_buf
// возвращает:
// 0 успех
// -1 не влезло
// [4 frame_len]
// [1 version]
// [1 type]
// [2 flags]
// [4 sender_id]
// [4 room_id]
// [8 timestamp]
// [4 msg_id]
// [payload]
int enqueue_packet(Client* c, Header* header, const uint8_t* msg, uint32_t len)
{
    if (!c || !header || (!msg && len > 0) || len > PAYLOAD_SIZE)
    {
        return -1;
    }
    // если пакет не влезает, делается смещение неотправленного в начало
    // -4 как проверка от переполнения
    uint32_t packet_size = FRAME_LEN_SIZE + HEADER_SIZE + len;
    if (packet_size > BUF_SIZE - c->conn.out_len)
    {
        if (c->conn.out_sent > 0)
        {
            memmove(c->conn.out_buf, c->conn.out_buf + c->conn.out_sent,
                    c->conn.out_len - c->conn.out_sent);
            c->conn.out_len -= c->conn.out_sent;
            c->conn.out_sent = 0;
        }
    }
    // если не влезло даже после смещения влево, ошибка
    if (packet_size > BUF_SIZE - c->conn.out_len)
    {
        return -1;
    }
    // [4 frame_len]
    uint32_t frame_len = htonl(HEADER_SIZE + len);
    memcpy(c->conn.out_buf + c->conn.out_len, &frame_len, FRAME_LEN_SIZE);
    c->conn.out_len += FRAME_LEN_SIZE;

    //[1 version]
    uint8_t hv = header->version;

    memcpy(c->conn.out_buf + c->conn.out_len, &hv, VERSION_SIZE);
    c->conn.out_len += VERSION_SIZE;

    //[1 type]
    uint8_t type = header->type;
    memcpy(c->conn.out_buf + c->conn.out_len, &type, TYPE_SIZE);
    c->conn.out_len += TYPE_SIZE;

    // [2 flags]
    // -1 не влезло
    // [4 frame_len]
    uint16_t flags = htons(header->flags);
    memcpy(c->conn.out_buf + c->conn.out_len, &flags, FLAGS_SIZE);
    c->conn.out_len += FLAGS_SIZE;

    // [4 sender_id]
    uint32_t sender_id = htonl(header->sender_id);
    memcpy(c->conn.out_buf + c->conn.out_len, &sender_id, SENDER_ID_SIZE);
    c->conn.out_len += SENDER_ID_SIZE;

    // [4 room_id]
    uint32_t room_id = htonl(header->room_id);
    memcpy(c->conn.out_buf + c->conn.out_len, &room_id, ROOM_ID_SIZE);
    c->conn.out_len += ROOM_ID_SIZE;

    // [8 timestamp]
    uint64_t timestamp = htonll(header->timestamp);
    memcpy(c->conn.out_buf + c->conn.out_len, &timestamp, TIMESTAMP_SIZE);
    c->conn.out_len += TIMESTAMP_SIZE;

    // [4 msg_id]
    uint32_t msg_id = htonl(header->message_id);
    memcpy(c->conn.out_buf + c->conn.out_len, &msg_id, MESSAGE_ID_SIZE);
    c->conn.out_len += MESSAGE_ID_SIZE;

    // [payload]
    if (len > 0)
    {
        if (!msg)
        {
            return -1;
        }
        memcpy(c->conn.out_buf + c->conn.out_len, msg, len);
    }
    c->conn.out_len += len;
    return 0;
}

// [4 frame_len]
// [1 version]
// [1 type]
// [2 flags]
// [4 sender_id]
// [4 room_id]
// [8 timestamp]
// [4 msg_id]
// [payload]
int try_pop_packet(Client* c, Header* header, uint8_t* dst, uint32_t* dst_len)
{
    size_t off = 0;
    // [4 frame_len]
    uint32_t len;
    if (c->conn.in_len < FRAME_LEN_SIZE)
    {
        return 0;
    }
    memcpy(&len, c->conn.in_buf, FRAME_LEN_SIZE);
    off += FRAME_LEN_SIZE;
    len = ntohl(len);
    if (len > HEADER_SIZE + PAYLOAD_SIZE || len == 0 || len < HEADER_SIZE)
    {
        return -2;
    }
    if (c->conn.in_len < FRAME_LEN_SIZE + len)
    {
        return 0;
    }
    // [1 version]
    memcpy(&header->version, c->conn.in_buf + off, VERSION_SIZE);
    off += VERSION_SIZE;
    // [1 type]
    memcpy(&header->type, c->conn.in_buf + off, TYPE_SIZE);
    off += TYPE_SIZE;
    // [2 flags]
    memcpy(&header->flags, c->conn.in_buf + off, FLAGS_SIZE);
    off += FLAGS_SIZE;
    // [4 sender_id]
    memcpy(&header->sender_id, c->conn.in_buf + off, SENDER_ID_SIZE);
    off += SENDER_ID_SIZE;
    // [4 room_id]
    memcpy(&header->room_id, c->conn.in_buf + off, ROOM_ID_SIZE);
    off += ROOM_ID_SIZE;
    // [8 timestamp]
    memcpy(&header->timestamp, c->conn.in_buf + off, TIMESTAMP_SIZE);
    off += TIMESTAMP_SIZE;
    // [4 msg_id]
    memcpy(&header->message_id, c->conn.in_buf + off, MESSAGE_ID_SIZE);
    off += MESSAGE_ID_SIZE;
    // [payload]
    // -1 не влезло
    // [4 frame_len]
    size_t payload_len = len - HEADER_SIZE;
    if (payload_len > PAYLOAD_SIZE)
    {
        return -2;
    }
    memcpy(dst, c->conn.in_buf + off, payload_len);
    *dst_len = payload_len;

    size_t packet_size = FRAME_LEN_SIZE + len;
    if (packet_size > c->conn.in_len)
    {
        return 0;
    }
    memmove(c->conn.in_buf, c->conn.in_buf + packet_size, c->conn.in_len - packet_size);
    c->conn.in_len -= (packet_size);

    header->flags      = ntohs(header->flags);
    header->sender_id  = ntohl(header->sender_id);
    header->room_id    = ntohl(header->room_id);
    header->timestamp  = ntohll(header->timestamp);
    header->message_id = ntohl(header->message_id);
    return 1;
}

// recv в in_buf
// возвращает
// bytes > 0 при успехе
// 0 пока нет данных
// -1 соединение закрыто
// -2 ошибка
int recv_into_inbuf(Client* c)
{
    if (c->conn.in_len > BUF_SIZE)
    {
        return -2;
    }

    if (c->conn.in_len == BUF_SIZE)
    {
        // места больше нет, а try_pop_packet ничего не смог съесть
        return -2;
    }
    ssize_t bytes = recv(c->ei.fd, c->conn.in_buf + c->conn.in_len, BUF_SIZE - c->conn.in_len, 0);
    if (bytes == 0)
    {
        return -1;
    }
    if (bytes < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return 0;
        }
        else
        {
            return -2;
        }
    }
    c->conn.in_len += bytes;
    return bytes;
}

// возвращает
// 0 при успешной отправке или неготовности сокета
// -1 при ошибке
int flush_send(Client* c)
{
    while (c->conn.out_sent < c->conn.out_len)
    {
        ssize_t bytes = send(c->ei.fd, c->conn.out_buf + c->conn.out_sent,
                             c->conn.out_len - c->conn.out_sent, 0);
        if (bytes < 0)
        {
            // сокет не готов
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return 0;
            }
            // ошибка
            else
            {
                perror("send");
                return -1;
            }
        }
        else if (bytes == 0)
        {
            return -1;
        }
        else
        {
            c->conn.out_sent += bytes;
        }
    }
    if (c->conn.out_sent == c->conn.out_len)
    {
        c->conn.out_sent = 0;
        c->conn.out_len  = 0;
    }
    return 0;
}

// pop пакета из in_buf в dst и dst_len
// dst должен быть размером PAYLOAD_SIZE
// 1 при успешном извлечении
// 0 в буфере нет полного ответа
// -2 ошибка протокола
