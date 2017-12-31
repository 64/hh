#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include "stream.h"
#include "log.h"

#define STREAMTAB_INITIAL_LEN 64

// Shamelessly stolen from NGHTTP2
// https://github.com/nghttp2/nghttp2/blob/master/lib/nghttp2_map.c#L86
static uint32_t hash(int32_t key, uint32_t mod) {
	uint32_t h = (uint32_t)key;
	h ^= (h >> 20) ^ (h >> 12);
	h ^= (h >> 7) ^ (h >> 4);
	return h & (mod - 1);
}


void streamtab_alloc(struct streamtab *tab) {
	tab->entries = 0;
	tab->len = STREAMTAB_INITIAL_LEN;
	tab->streams = calloc(tab->len, sizeof(struct stream *));
	tab->root = stream_alloc();
	tab->streams[hash(0, tab->len)] = tab->root;
	memset(tab->root, 0, sizeof(struct stream));
	tab->root->weight = 256;
	tab->root->state = HH_STREAM_CLOSED;
	tab->root->req.fd = -1;
}

/*static void resize(struct streamtab *tab) {
	(void)tab;
}*/

void streamtab_insert(struct streamtab *tab, struct stream *stream) {
	// TODO: Resize if load is too high
	assert(stream->next == NULL);
	uint32_t idx = hash(stream->id, tab->len);
	stream->next = tab->streams[idx];
	tab->streams[idx] = stream;
	tab->entries++;
}

struct stream *streamtab_find_id(struct streamtab *tab, uint32_t stream_id) {
	uint32_t idx = hash(stream_id, tab->len);
	struct stream *tmp;
	for (tmp = tab->streams[idx]; tmp != NULL; tmp = tmp->next) {
		if (tmp->id == stream_id)
			return tmp;
	}
	return NULL;
}

// TODO: Implement scheduling based on weight and priority; don't use recursion
static struct stream *find_active(struct stream *s) {
	if (s == NULL)
		return NULL;
	else if (s->req.state == HH_REQ_IN_PROGRESS)
		return s;
	struct stream *rv = find_active(s->siblings);
	if (rv != NULL)
		return rv;
	return find_active(s->children);
}

struct stream *streamtab_schedule(struct streamtab *tab) {
	return find_active(streamtab_root(tab));
}

void streamtab_free(struct streamtab *tab) {
	for (uint32_t i = 0; i < tab->len; i++) {
		struct stream *tmp, *next;
		for (tmp = tab->streams[i]; tmp != NULL; tmp = next) {
			next = tmp->next;
			stream_free(tmp);
		}
	}
	free(tab->streams);
}

struct stream *stream_alloc(void) {
	struct stream *rv = malloc(sizeof *rv);
	memset(rv, 0, sizeof *rv);
	rv->state = HH_STREAM_IDLE;
	rv->req.fd = -1;
	return rv;
}

void stream_add_child(struct stream *stream, struct stream *child) {
	assert(child->parent == NULL);
	child->parent = stream;
	if (stream->children == NULL) {
		stream->children = child;
	} else {
		struct stream *start = stream->children;
		while (start->siblings != NULL)
			start = start->siblings;
		start->siblings = child;
	}
}

void stream_add_exclusive_child(struct stream *stream, struct stream *child) {
	assert(child->parent == NULL);
	assert(child->children == NULL);
	child->parent = stream;
	if (stream->children == NULL)
		stream->children = child;
	else {
		child->children = stream->children;
		stream->children = child;
	}
}

int stream_change_state(struct stream *stream, enum stream_state new_state) {
	assert(stream->id != 0);
	
	if (new_state == HH_STREAM_CLOSED && stream->req.state == HH_REQ_IN_PROGRESS) {
		stream->req.state = HH_REQ_DONE;
		request_cleanup(&stream->req);
	}

	switch (stream->state) {
		case HH_STREAM_IDLE:
			switch (new_state) {
				case HH_STREAM_HCLOSED_REMOTE:
				case HH_STREAM_OPEN:
					stream->state = new_state;
					break;
				default:
					goto verybad;
			}
			break;
		case HH_STREAM_OPEN:
			switch (new_state) {
				case HH_STREAM_OPEN:
					break;
				case HH_STREAM_CLOSED:
					stream->state = new_state;
					// TODO: Reprioritise children
					break;
				case HH_STREAM_HCLOSED_REMOTE:
				case HH_STREAM_HCLOSED_LOCAL:
					stream->state = new_state;
					break;
				default:
					goto verybad;
			}
			break;
		case HH_STREAM_HCLOSED_REMOTE:
			switch (new_state) {
				case HH_STREAM_HCLOSED_LOCAL:
					// Go to CLOSED instead
					stream->state = HH_STREAM_CLOSED;
					stream->how_closed.remote = 0;
					stream->how_closed.rst_stream = 0;
					break;
				case HH_STREAM_CLOSED:
					stream->state = new_state;
					stream->how_closed.remote = 0; // TODO: Get this information somehow
					stream->how_closed.rst_stream = 1;
					break;
				default:
					goto verybad;
			}
			break;
		case HH_STREAM_HCLOSED_LOCAL:
			switch (new_state) {
				case HH_STREAM_HCLOSED_REMOTE:
					// Go to CLOSED instead
					stream->state = HH_STREAM_CLOSED;
					stream->how_closed.remote = 1;
					stream->how_closed.rst_stream = 0;
					break;
				case HH_STREAM_CLOSED:
					stream->state = new_state;
					stream->how_closed.remote = 0; // TODO: Get this information somehow
					stream->how_closed.rst_stream = 1;
					break;
				default:
					goto verybad;
			}
			break;
		default:
		verybad:
			// TODO: Error handle
			log_debug("Unknown stream state transition from %d to %d", stream->state, new_state);
			abort();
			break;
	}
	return 0;
}

void stream_free(struct stream *stream) {
	if (stream->req.fd != -1) {
		int rv = close(stream->req.fd);
		if (rv != 0) {
			log_warn("Call to close failed (%s)", strerror(errno));
		}
	}
	free(stream);
}
