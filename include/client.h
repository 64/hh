#pragma once
#include <s2n.h>

struct client {
	int fd; // This must be first, because of a little epoll hack we use
	struct s2n_connection *tls;
	enum {
		HH_IDLE,
		HH_NEGOTIATING_TLS
	} state;
	s2n_blocked_status blocked;
};

struct client *client_new(int);
void client_free(struct client *);
