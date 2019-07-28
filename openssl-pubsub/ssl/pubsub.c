#include "<openssl/pubsub.h>"
#include "logs.h"

// Inside SSL_CTX
struct ps_state_st *init_ps_state_table(void)
{
  fstart();
  struct ps_state_table_st *ret;
  ret = (struct ps_state_table_st *)malloc(sizeof(struct ps_state_table_st));
  memset(ret, 0x0, sizeof(struct ps_state_table_st));
  fend();
  return ret;
err:
  return NULL;
}

// Inside SSL_CTX
void free_ps_state_table(SSL_CTX *ctx)
{
  fstart("ctx: %p", ctx);
  struct ps_state_table_st *table;
  struct ps_state_st *prev, *curr;

  if (table)
  {
    curr = table->head;
    while (curr)
    {
      prev = curr;
      curr = curr->next;
      free_ps_state(prev);
    }
    table->num = -1;
    free(table);
    table = NULL;
  }
  
  fend();
  return SUCCESS;
}

void print_ps_state_table(SSL *s)
{
  fstart("s: %p", s);
  int idx;
  struct ps_state_table_st *table;
  struct ps_state_st *ps_state;
  
  idx = 0;
  table = s->ctx->table;
  if (!table) goto err;
  ps_state = table->head;
  if (!ps_state) goto err;

  psdebug("Number of PS State: %d\n", table->num);
  while (ps_state)
  {
    psdebug("===== (Index: %d) =====", idx++);
    psdebug("Topic (%d bytes): %s", ps_state->tlen, ps_state->topic);
    psdebug("Key Length: %d", ps_state->klen);
    psdebug("=======================\n");
  }

  fend();
err:
  ferr();
}

struct ps_state_st *init_ps_state(void)
{
  fstart();
  struct ps_state_st *ret;
  ret = (struct ps_state_st *)malloc(sizeof(struct ps_state_st));
  if (!ret) goto err;
  memset(ret, 0x0, sizeof(struct ps_state_st));
  fend();
  return ret;
err:
  ferr();
  return NULL;
}

void free_ps_state(struct ps_state_st *state)
{
  fstart("state: %p", state);
  if (state)
  {
    if (state->key)
      free(state->key);
    state->key = NULL;
    state->klen = -1;
    if (state->topic)
      free(state->topic);
    state->topic = NULL;
    state->tlen = -1;
  }
  fend();
}

int add_ps_state_to_table(SSL *s, struct ps_state_st *ps_state)
{
  fstart("s: %p, ps_state: %p", s, ps_state);
  struct ps_state_table_st *table;
  struct ps_state_st *head, *tail;
  table = s->ctx->table;
  head = table->head;
  tail = table->tail;

  if (!head)
  {
    head = state;
    tail = head;
  }
  else
  {
    if (!tail)
      tail = state;
    else
      tail->next = state;
  }

  fend();
  return SUCCESS;
}

struct ps_state_st *get_ps_state_from_table(SSL *s, unsigned char *topic, int tlen)
{
  fstart("s: %p, topic: %p, tlen: %d", s, topic, tlen);
  struct ps_state_st *state, *ret;
  state = s->ctx->ps_state_table->head;

  ret = NULL;
  while (state)
  {
    if (state->tlen == tlen)
    {
      if (!strcmp(state->topic, topic))
      {
        ret = state;
        break;
      }
    }
    state = state->next;
  }

  fend();
  return ret;
}

int set_topic(SSL *s, unsigned char *topic, int tlen)
{
  fstart("s: %p, topic: %p, tlen: %d", s, topic, tlen);
  struct ps_state_st *ps_state;
  ps_state = get_ps_state_from_table(s, topic, tlen);

  if (!ps_state)
  {
    ps_state = init_ps_state();
    ps_state->topic = (unsigned char *)malloc(tlen);
    memcpy(ps_state->topic, topic, tlen);
    ps_state->tlen = tlen;
    add_ps_state_to_table(s, ps_state);
  }

  fend();
  return SUCCESS;
err:
  ferr();
  return FAILURE;
}

int set_topic_group_key(SSL *s, unsigned char *topic, int tlen, 
    unsigned char *key, int klen)
{
  fstart("s: %p, topic: %p, tlen: %d, key: %p, klen: %d", s, key, klen);
  struct ps_state_st *ps_state;
  ps_state = get_ps_state_from_table(s, topic, tlen);

  if (ps_state)
  {
    if (ps_state->key)
    {
      free(ps_state->key);
    }
  }
  else
  {
    ps_state = init_ps_state();
    ps_state->topic = (unsigned char *)malloc(tlen);
    memcpy(ps_state->topic, topic, tlen);
    ps_state->tlen = tlen;
    add_ps_state_to_table(s, ps_state);
  }
  ps_state->key = (unsigned char *)malloc(klen);
  memcpy(ps_state->key, key, klen);
  ps_state->klen = klen;

  fend();
  return SUCCESS;
err:
  ferr();
  return FAILURE;
}

int get_topic(SSL *s, unsigned char *topic, int *tlen)
{
  fstart("s: %p, topic: %p, tlen: %d", s, topic, tlen);
  struct ps_state_st *ps_state;
  ps_state = get_ps_state_from_table(s, topic, tlen);

  if (!ps_state) goto err;
  if (!ps_state->topic) goto err;
  topic = ps_state->topic;
  tlen = ps_state->tlen;

  fend();
  return SUCCESS;
err:
  ferr();
  return FAILURE;
}

int get_topic_group_key(SSL *s, unsigned char *topic, int tlen, 
    unsigned char *key, int *klen)
{
  fstart("s: %p, topic: %p, tlen: %d, key: %p, klen: %d", s, key, klen);
  struct ps_state_st *ps_state;
  ps_state = get_ps_state_from_table(s, topic, tlen);

  if (!ps_state) goto err;
  if (!(ps_state->key)) goto err;

  key = ps_state->key;
  *klen = ps_state->klen;

  fend();
  return SUCCESS;
err:
  ferr();
  return FAILURE;
}

int get_topic_group_sequence(SSL *s, unsigned char *topic, int tlen)
{
  fstart("s: %p, topic: %s, tlen: %d", s, topic, tlen);
  int ret;
  struct ps_state_st *ps_state;

  ps_state = get_ps_state_from_table(s, topic, tlen);
  if (!ps_state) goto err;

  fend();
  return ps_state->sequence;
err:
  ferr();
  return FAILURE;
}
