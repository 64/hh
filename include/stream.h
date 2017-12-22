#pragma once

#include <stdint.h>
#include <stddef.h>

struct stream {
	uint32_t id;
	uint16_t weight;
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
	struct stream *children; // List of streams that are dependent on this one
	struct stream *next; // For when the stream is closed, but not freed
};

struct stream *stream_alloc(void);
void stream_free(struct stream *);


