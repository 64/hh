#pragma once

#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include "request.h"

enum stream_state {
	HH_STREAM_IDLE,
	HH_STREAM_RESERVED_LOCAL,
	HH_STREAM_RESERVED_REMOTE,
	HH_STREAM_OPEN,
	HH_STREAM_HCLOSED_LOCAL,
	HH_STREAM_HCLOSED_REMOTE,
	HH_STREAM_CLOSED
};

struct stream {
	uint32_t id;
	uint16_t weight; // TODO: Maybe make this a uint8_t
	enum stream_state state;
	struct {
		int remote : 1;
		int rst_stream : 1;
	} how_closed;
	size_t window_size;
	struct request req;
	struct stream *children, *parent, *siblings;
	struct stream *next;
};

struct streamtab {
	size_t entries;
	size_t len;
	struct stream *root;
	struct stream **streams;
};

void streamtab_alloc(struct streamtab *);
void streamtab_insert(struct streamtab *, struct stream *);
struct stream *streamtab_schedule(struct streamtab *, size_t *);
struct stream *streamtab_find_id(struct streamtab *, uint32_t);
void streamtab_free(struct streamtab *);

struct stream *stream_alloc(void);
void stream_add_child(struct stream *stream, struct stream *child);
void stream_add_exclusive_child(struct stream *stream, struct stream *child);
int stream_change_state(struct stream *stream, enum stream_state new_state);
void stream_free(struct stream *);

static inline struct stream *streamtab_root(struct streamtab *tab) {
	struct stream *s = streamtab_find_id(tab, 0);
	assert(s != NULL);
	return s;
}

