#ifndef PACKET_IO_H
#define PACKET_IO_H

#include "transport/connection.h"

int enqueue_packet(Client* c, Header* header, const uint8_t* msg, uint32_t len);

// pop пакета из in_buf в dst и dst_len
// dst должен быть размером хотя бы PAYLOAD_SIZE + 1
// 1 при успешном извлечении
// 0 в буфере нет полного ответа
// -2 ошибка протокола
int try_pop_packet(Client* c, Header* header, uint8_t* dst, uint32_t* dst_len);

// recv в in_buf
// возвращает
// bytes > 0 при успехе
// 0 пока нет данных
// -1 соединение закрыто
// -2 ошибка
int recv_into_inbuf(Client* c);

// отправить все возможное из out_buf
int flush_send(Client* c);

#endif // PACKET_IO_H