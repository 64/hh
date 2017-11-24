#pragma once
#include <s2n.h>

#include "frame.h"

struct client {
	int fd; // This must be first, because of a little epoll hack we use
	struct s2n_connection *tls;
	enum client_state {
		HH_IDLE, // Connection is ready for general HTTP/2 use
		HH_NEGOTIATING_TLS, // Connection initiated, doing TLS negotiation
		HH_WAITING_MAGIC, // Waiting for client to send connection preface
		HH_WAITING_SETTINGS, // Waiting for client to send initial SETTINGS frame
		HH_TLS_SHUTDOWN, // Sent TLS alert, waiting for acknowledgement
	} state;
	s2n_blocked_status blocked;
	struct ib_frame ib_frame;
};

struct client *client_new(int);
void client_free(struct client *);
int close_client(struct client *);

int client_on_write_ready(struct client *);
int client_on_data_received(struct client *);
