#ifndef __PUBSUB_H__
#define __PUBSUB_H__

#include <openssl/ssl.h>
#define STATE_FILE "state"

struct ps_state_st {
  int state;
  unsigned char *topic;
  int tlen;
  unsigned char *key;
  int klen;
  int sequence;
  struct ps_state_st *next;
};

struct ps_state_table_st {
  int num;
  struct ps_state_st *head;
  struct ps_state_st *tail;
};

struct ps_state_table_st *init_ps_state_table(void);
void free_ps_state_table(SSL_CTX *ctx);
void print_ps_state_table(SSL *s);

struct ps_state_st *init_ps_state(void);
void free_ps_state(struct ps_state_st *state);
void add_ps_state_to_table(SSL *s, struct ps_state_st *state);
struct ps_state_st *get_ps_state_from_table(SSL *s, unsigned char *topic, int tlen);

int set_topic(SSL *ssl, unsigned char *topic, int tlen);
int set_key(SSL *ssl, unsigned char *key, int klen);

int get_topic(SSL *ssl, unsigned char *topic, int tlen);
int get_key(SSL *ssl, unsigned char *key, int *klen);
int get_sequence(SSL *ssl);

int need_handshake(SSL *ssl);
int do_process_pubsub(SSL *ssl, void *buf, int *len);
int do_pubsub_handshake(SSL *ssl, void *buf, int *len);
int do_pubsub_record(SSL *ssl, void *buf, int *len);

#endif /* __PUBSUB_H__ */
