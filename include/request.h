#pragma once

struct client;
struct stream;

#define REQ_MAX_PATH 50

struct request {
	struct client *client; // Client who initiated the request
	struct request *next;
	int fd; // File descriptor of whatever resource is being accessed
	union {
		char pathbuf[REQ_MAX_PATH]; // Path to the file being accessed
		char *pathptr;
	};
	struct {
		int has_path : 1;
		int has_method : 1;
		int has_scheme : 1;
		int done : 1;
	} pseudos;
	enum {
		HH_REQ_NOT_STARTED,
		HH_REQ_IN_PROGRESS,
		HH_REQ_DONE
	} state;
	int status_code; // HTTP status code
};

void request_send_headers(struct client *, struct stream *);
int request_fulfill(struct stream *s, uint8_t *buf, size_t *max_size);
void request_cleanup(struct request *req);
