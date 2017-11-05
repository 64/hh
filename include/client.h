#pragma once
#include <s2n.h>

struct client {
	int fd; // This must be first, because of a little epoll hack we use
	struct s2n_connection *tls;
};

struct client *client_new(int);
void client_free(struct client *);
