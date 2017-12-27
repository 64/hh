#pragma once

struct client;
struct stream;

struct request {
	struct client *client; // Client who initiated the request
	int fd; // File descriptor of whatever resource is being accessed
	char *path;
	struct {
		int has_path : 1;
		int has_method : 1;
		int has_scheme : 1;
		int done : 1;
	} pseudos;
	struct request *next;
};

void request_send_headers(struct client *, struct stream *);
