#pragma once

#include <stdint.h>
#include <stddef.h>

struct stream {
	uint32_t id;
	uint16_t weight; // TODO: Maybe make this a uint8_t
	size_t window_size;
	enum {
		HH_STREAM_IDLE,
		HH_STREAM_RESERVED_LOCAL,
		HH_STREAM_RESERVED_REMOTE,
		HH_STREAM_OPEN,
		HH_STREAM_HCLOSED_LOCAL,
		HH_STREAM_HCLOSED_REMOTE,
		HH_STREAM_CLOSED
	} state;
	struct stream *children, *parent, *siblings;
};

struct stream *stream_alloc(void);
void stream_add_child(struct stream *stream, struct stream *child);
void stream_add_exclusive_child(struct stream *stream, struct stream *child);
struct stream *stream_find_id(struct stream *stream, uint32_t id);
void stream_free_all(struct stream *root);
void stream_free(struct stream *);

