#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "request.h"
#include "stream.h"
#include "cashpack.h"
#include "frame.h"
#include "log.h"

#define MAX_HEADER_FIELDS 64
#define HEADER(name, value) fields[pos++] = (struct hpack_field){ \
		.nam = (name), \
		.val = (value), \
		.flg = HPACK_FLG_TYP_LIT | HPACK_FLG_NAM_HUF | HPACK_FLG_VAL_HUF \
	}

// TODO: Better allocation
void request_send_headers(struct client *client, struct stream *stream) {
	struct hpack_field fields[MAX_HEADER_FIELDS];
	char content_length[10] = { 0 };
	size_t pos = 0;
	bool end_stream = false;

	switch (stream->req.status_code) {
		case 500:
			HEADER(":status", "500");
			end_stream = true;
			break;
		case 404:
			HEADER(":status", "404");
			end_stream = true;
			break;
		case 400:
			HEADER(":status", "400");
			end_stream = true;
			break;
		case 200:
			HEADER(":status", "200");
			// Set content-type depending on file extension
			char *extension = strrchr(stream->req.pathptr, '.');
			if (extension == NULL) {
				log_warn("Retrieved file '%s' with no extension.", stream->req.pathptr);
			} else {
				extension++;
				if (strcmp(extension, "html") == 0)
					HEADER("content-type", "text/html");
				else if (strcmp(extension, "js") == 0)
					HEADER("content-type", "application/javascript");
				else if (strcmp(extension, "css") == 0)
					HEADER("content-type", "text/css");
				else if (strcmp(extension, "png") == 0)
					HEADER("content-type", "image/png");
				else if (strcmp(extension, "jpg") == 0) {
					HEADER("content-type", "image/jpg");
					// For the tiled images test
					HEADER("cache-control", "no-cache, no-store"); 
				}
			}

			struct stat statbuf;
			if (fstat(stream->req.fd, &statbuf) < 0) {
				log_warn("Call to fstat failed (%s)", strerror(errno));
			} else {
				snprintf(content_length, 10, "%zu", statbuf.st_size);
				HEADER("content-length", content_length);
			}

			break;
		default:
			log_trace();
			//__builtin_unreachable();
	}

	assert(pos < MAX_HEADER_FIELDS);

	if (end_stream)
		stream_change_state(stream, HH_STREAM_HCLOSED_LOCAL);
	else
		stream->req.state = HH_REQ_IN_PROGRESS;

	if (send_headers(client, stream->id, fields, pos, end_stream) != 0)
		abort();
}

// TODO: Padding etc
int request_fulfill(struct stream *s, uint8_t *buf, size_t *max_size) {
	assert(s->req.fd != -1);
	assert(*max_size != 0 && *max_size + HH_HEADER_SIZE < (1 << 25));
	assert(*max_size > HH_HEADER_SIZE); // TODO: Remove this assert
	uint8_t *ptr = buf + HH_HEADER_SIZE; // Move forwards 9 bytes for frame header
	size_t remaining = *max_size - HH_HEADER_SIZE;
	ssize_t nwritten;
	uint32_t total_nwritten = 0;
	uint8_t flags = 0;
	while ((nwritten = read(s->req.fd, ptr, remaining)) > 0) {
		remaining -= (size_t)nwritten;
		ptr += nwritten;
		total_nwritten += (uint32_t)nwritten;
		if (remaining == 0)
			break;
	}
	if (nwritten == 0) {
		// EOF, set END_STREAM and close
		// Will automagically go to HH_STREAM_CLOSED if already in HH_STREAM_HCLOSED_REMOTE
		stream_change_state(s, HH_STREAM_HCLOSED_LOCAL);
		flags |= HH_END_STREAM;
		s->req.state = HH_REQ_DONE;
		if (close(s->req.fd) != 0)
			log_warn("Call to close failed (%s)", strerror(errno));
		s->req.fd = -1;
	} else if (nwritten < 0) {
		log_warn("Call to read failed (%s)", strerror(errno));
		return -1;
	}
	construct_frame_header((struct frame_header *)buf, total_nwritten, flags, HH_FT_DATA, s->id);
	*max_size = total_nwritten + HH_HEADER_SIZE;
	return 0;
}

void request_cleanup(struct request *req) {
	int rv = close(req->fd);
	req->state = HH_REQ_DONE;
	if (rv != 0) {
		log_warn("Call to close failed (%s)", strerror(errno));
	}
	req->fd = -1;
}
