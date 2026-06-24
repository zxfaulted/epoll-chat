#ifndef AUTH_H
#define AUTH_H

#include "transport/connection.h"
#include <openssl/evp.h>
#include <stdint.h>

#define AUTH_CHALLENGE_NONCE_LEN 32
#define AUTH_CHALLENGE_PAYLOAD_LEN (SENDER_ID_LEN + AUTH_CHALLENGE_NONCE_LEN)

#define MAX_PENDING_REGISTRATIONS 128
#define REGISTRATION_TTL_SECONDS 60
#define CHALLENGE_LEN 32

typedef struct PendingReg
{
    char     name[MAX_NAME_LEN + 1];
    uint32_t id;
    uint8_t  challenge[32];
    uint64_t expires_at;
    int      used;
} PendingReg;

int  get_challenge(uint8_t challenge[CHALLENGE_LEN]);
int  get_sign_challenge(uint32_t client_id, const char* name, uint8_t* msg, uint16_t msg_len,
                        EVP_PKEY* private_key, unsigned char** out, size_t* out_len);
int  server_verify_challenge(Client* c, uint8_t* msg, uint16_t msg_len);
int  server_send_challenge(int epfd, Client* c, uint32_t challenger_id, uint8_t* out_challenge,
                           uint32_t* message_id);
int  get_sign_register_commit(uint32_t client_id, const char* name, const uint8_t* nonce,
                              EVP_PKEY* private_key, const uint8_t* identity_pub_der,
                              uint16_t identity_pub_der_len, unsigned char** out, size_t* out_len);
int  verify_register_commit(uint32_t client_id, const char* name, uint8_t* nonce, uint8_t* msg,
                            uint16_t msg_len, EVP_PKEY** out_identity_pub);
int  add_pending_registration(PendingReg* pr, const char* name, uint8_t* challenge,
                              uint32_t client_id);
void remove_pending_registration(PendingReg* pr, const char* name, uint32_t client_id);
int  find_in_pending_registrations(PendingReg* pr, const char* name, uint32_t client_id);
int  server_send_registration_challenge(int epfd, Client* c, uint32_t temp_client_id,
                                        const uint8_t challenge[CHALLENGE_LEN],
                                        uint32_t*     message_id);

#endif