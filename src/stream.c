#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "stream.h"
#include "log.h"

struct stream *stream_alloc(void) {
	struct stream *rv = malloc(sizeof *rv);
	memset(rv, 0, sizeof *rv);
	rv->state = HH_STREAM_IDLE;
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

// TODO: Don't use recursion
struct stream *stream_find_id(struct stream *stream, uint32_t id) {
	if (stream == NULL)
		return NULL;
	else if (stream->id == id)
		return stream;
	struct stream *tmp = stream_find_id(stream->siblings, id);
	if (tmp != NULL)
		return tmp;
	return stream_find_id(stream->children, id);
}

int stream_change_state(struct stream *stream, enum stream_state new_state) {
	switch (stream->state) {
		case HH_STREAM_IDLE:
			switch (new_state) {
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

// TODO: Don't use recursion
void stream_free_all(struct stream *root) {
	if (root == NULL)
		return;
	stream_free_all(root->siblings);
	stream_free_all(root->children);
	stream_free(root);
}

void stream_free(struct stream *stream) {
	free(stream);
}
