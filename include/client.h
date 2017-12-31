#pragma once
#include <s2n.h>
#include <stdbool.h>

#include "frame.h"
#include "pqueue.h"
#include "stream.h"
#include "request.h"
#include "cashpack.h"
#include "util.h"

#define CLIENT_EPOLL_EVENTS (EPOLLIN | EPOLLET | EPOLLRDHUP)

struct h2_settings {
	uint32_t header_table_size;
	uint32_t enable_push;
	uint32_t max_concurrent_streams;
	uint32_t initial_window_size;
	uint32_t max_frame_size;
	uint32_t max_header_list_size;
};

struct client {
	int fd; // This must be first, because of a little epoll hack we use
	int timer_fd;
	struct s2n_connection *tls;
	enum client_state {
		HH_IDLE, // Connection is ready for general HTTP/2 use
		HH_NEGOTIATING_TLS, // Connection initiated, doing TLS negotiation
		HH_WAITING_MAGIC, // Waiting for client to send connection preface
		HH_WAITING_SETTINGS, // Waiting for client to send initial SETTINGS frame
		HH_GOAWAY, // GOAWAY frame sent, about to shut down client
		HH_BLINDED, // Blinded by s2n, waiting for timer to expire
		HH_TLS_SHUTDOWN, // Sent TLS alert, waiting for acknowledgement
		HH_ALREADY_CLOSED, // Socket already closed
	} state;
	s2n_blocked_status blocked;
	bool is_write_blocked;
	bool is_closing;
	bool end_stream;
	uint32_t continuation_on_stream;
	uint32_t highest_stream_seen;
	size_t window_size;
	uint8_t *hdblock; // Big buffer for header decoding
	struct ib_frame ib_frame;
	struct pqueue pqueue;
	struct h2_settings settings;
	struct hpack *encoder;
	struct hpack *decoder;
	struct streamtab streams;
};

void set_thread_state(struct thread_state *);
struct client *client_new(int, int);
void client_free(struct client *);
int client_write_flush(struct client *);
bool client_pending_write(struct client *);
void client_close_immediate(struct client *);
int client_close_graceful(struct client *);

int client_on_timer_expired(struct client *);
int client_on_write_ready(struct client *);
int client_on_data_received(struct client *);
