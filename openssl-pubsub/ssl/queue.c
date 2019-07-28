#include <openssl/ssl.h>
#include <openssl/queue.h>
#include "logs.h"

int init_message_queue(SSL_CTX *ctx)
{
  psdebug("Start: init_message_queue()");
  struct message_queue_st *queue;
  if (!ctx) goto err;
  queue = ctx->queue = (struct message_queue_st *)malloc(sizeof(struct message_queue_st));
  memset(queue, 0x0, sizeof(struct message_queue_st));
  psdebug("Finish: init_message_queue()");
  return SUCCESS;
err:
  psdebug("Error: init_message_queue()");
  return FAILURE;
}

void free_message_queue(SSL_CTX *ctx)
{
  psdebug("Start: free_message_queue()");
  struct message_st *curr, *next;

  if (ctx)
  {
    if (ctx->queue)
    {
      if (ctx->queue->num > 0)
      {
        curr = ctx->queue->head;
        next = curr->next;
        while (curr)
        {
          free_message(curr);
          curr = next;
          if (curr)
            next = curr->next;
        }
      }
      free(ctx->queue);
    }
  }
  psdebug("Finish: free_message_queue()");
}

struct message_queue_st *get_message_queue(SSL *s)
{
  return s->ctx->queue;
}

void print_message_queue(SSL *s)
{
  psdebug("Start: print_message_queue()");
  int idx;
  struct message_queue_st *queue;
  struct message_st *msg;
  queue = s->ctx->queue;
  msg = queue->head;

  psdebug("Number of Messages: %d\n", queue->num);
  idx = 0;
  while (msg)
  {
    psdebug("========== (index: %d) ==========", idx++);
    psdebug("Key: %s", msg->key);
    psdebug("Message: %s", msg->msg);
    psdebug("=================================\n");
    msg = msg->next;
  }
  psdebug("Finish: print_message_queue()");
}

struct message_st *init_message(unsigned char *key, int klen, unsigned char *msg, int mlen)
{
  psdebug("Start: init_message()");
  struct message_st *ret;
  ret = (struct message_st *)malloc(sizeof(struct message_st));

  ret->key = (unsigned char *)malloc(klen);
  if (!(ret->key)) goto err;
  memcpy(ret->key, key, klen);
  ret->klen = klen;

  ret->msg = (unsigned char *)malloc(mlen);
  if (!(ret->msg)) goto err;
  memcpy(ret->msg, msg, mlen);
  ret->mlen = mlen;

  ret->next = NULL;
  psdebug("Finish: init_message()");
  return ret;
err:
  psdebug("Error: init_message()");
  return NULL;
}

void free_message(struct message_st *msg)
{
  psdebug("Start: free_message()");
  if (msg)
  {
    if (msg->key)
      free(msg->key);
    msg->klen = 0;
    if (msg->msg)
      free(msg->msg);
    msg->mlen = 0;
  }
  psdebug("Finish: free_message()");
}

void add_message_to_queue(SSL *s, struct message_st *msg)
{
  psdebug("Start: add_message_to_queue()");
  struct message_queue_st *queue;
  queue = s->ctx->queue;
  if (!(queue->head))
    queue->head = msg;

  if (queue->tail)
    queue->tail->next = msg;
  queue->tail = msg;
  queue->num++;
  psdebug("Finish: add_message_to_queue()");
}

struct message_st *get_message_from_queue(SSL *s)
{
  psdebug("Start: get_message_from_queue()");
  struct message_queue_st *queue;
  struct message_st *msg;

  msg = queue->head;
  queue->head = msg->next;
  queue->num--;
  psdebug("Finish: get_message_from_queue()");
}
