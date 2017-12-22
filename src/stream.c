#include <stdlib.h>
#include <string.h>
#include "stream.h"

struct stream *stream_alloc(void) {
	struct stream *rv = malloc(sizeof *rv);
	memset(rv, 0, sizeof *rv);
	rv->state = HH_STREAM_IDLE;
	return rv;
}

void stream_free(struct stream *stream) {
	free(stream);
}
