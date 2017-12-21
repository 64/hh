#pragma once

#include <stddef.h>
#include <stdint.h>

#define BUF_SIZE 4096

struct buf_chain {
	struct buf_chain *next;
	size_t len;
	size_t offset;
	char data[BUF_SIZE];
};

struct client;

struct buf_chain *buf_alloc(void);
void buf_free_chain(struct buf_chain *chain);
struct buf_chain *buf_pop_chain(struct buf_chain **chain); // Returns a pointer that needs to be free'd
