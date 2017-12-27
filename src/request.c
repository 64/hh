#include <hpack.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>

#include "request.h"
#include "stream.h"
#include "frame.h"

#define MAX_HEADER_FIELDS 64

// TODO: Better allocation
void request_send_headers(struct client *client, struct stream *stream) {
	struct hpack_field fields[MAX_HEADER_FIELDS];
	size_t pos = 0;

	fields[pos++] = (struct hpack_field){ .nam = ":status", .val = "500", .flg = HPACK_FLG_TYP_DYN | HPACK_FLG_AUT_IDX };
	if (send_headers(client, stream->id, fields, pos) != 0) 
		abort();
}

