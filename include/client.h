#pragma once
#include <s2n.h>
#include <hpack.h>
#include <stdbool.h>

#include "frame.h"
#include "buf_chain.h"
#include "stream.h"

#define CLIENT_EPOLL_EVENTS (EPOLLIN | EPOLLET | EPOLLRDHUP)

struct h2_settings {
	uint32_t header_table_size;
	uint32_t enable_push;
	uint32_t max_concurrent_streams;
	uint32_t initial_window_size;
	uint32_t max_frame_size;
	uint32_t max_header_list_size;
};

enum write_pri {
	HH_PRI_HIGH,
	HH_PRI_MED,
	HH_PRI_LOW
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
		HH_CLOSED, // Already closed (client disconnected)
	} state;
	s2n_blocked_status blocked;
	bool is_write_blocked;
	bool expect_continuation;
	struct ib_frame ib_frame;
	struct buf_chain *low_pri_writes;
	struct buf_chain *med_pri_writes;
	struct buf_chain *high_pri_writes;
	struct h2_settings settings;
	struct hpack *decoder;
	//struct hpack *encoder;
	struct stream root_stream;
	size_t window_size;
};

struct client *client_new(int, int, int);
void client_free(struct client *);
int close_client(struct client *);
int client_queue_write(struct client *, enum write_pri, char *, size_t);

int client_on_timer_expired(struct client *);
int client_on_write_ready(struct client *);
int client_on_data_received(struct client *);
