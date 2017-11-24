#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <s2n.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include "client.h"
#include "log.h"
#include "util.h"

#define CLIENT_MAGIC "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define CLIENT_MAGIC_LEN 24

extern struct s2n_config *server_config;

struct client *client_new(int fd) {
	struct client *rv = malloc(sizeof(struct client));
	rv->tls = s2n_connection_new(S2N_SERVER);
	if (rv->tls == NULL) {
		log_warn("Call to s2n_connection_new failed (%s)", s2n_strerror(s2n_errno, "EN"));
		goto cleanup; // Probably caused by mlock limits
	}
	s2n_connection_set_fd(rv->tls, fd);
	s2n_connection_set_config(rv->tls, server_config);
	s2n_connection_set_blinding(rv->tls, S2N_SELF_SERVICE_BLINDING); // TODO: Implement blinding
	s2n_connection_set_ctx(rv->tls, rv);
	rv->fd = fd;
	rv->state = HH_NEGOTIATING_TLS;
	rv->blocked = S2N_NOT_BLOCKED;
	rv->ib_frame.remaining = 0;
	return rv;
cleanup:
	free(rv);
	return NULL;
}

void client_free(struct client *client) {
	if (client != NULL) {
		s2n_connection_free(client->tls); // TODO: Wipe the connection, don't free it
		free(client);
	}
}

int close_client(struct client *client) {
	int rv = close(client->fd);
	if (rv < 0)
		log_warn("Call to close(client) failed (%s)", strerror(errno));
	client_free(client);
	return rv;
}

// Big state machine.
static int change_state(struct client *client, enum client_state to) {
	switch (client->state) {
		case HH_IDLE:
			switch (to) {
				case HH_TLS_SHUTDOWN:
					client->state = to;
					break;
				default:
					goto verybad;
			}
			break;
		case HH_WAITING_MAGIC:
			if (to != HH_WAITING_SETTINGS)
				goto verybad;
			client->state = to;
			break;
		case HH_WAITING_SETTINGS:
			if (to != HH_IDLE)
				goto verybad;
			client->state = to;
			break;
		case HH_NEGOTIATING_TLS:
			switch (to) {
				case HH_WAITING_MAGIC:
					client->state = to;
					client->ib_frame.remaining = CLIENT_MAGIC_LEN;
					// Send server SETTINGS frame
					break;
				default:
					goto verybad;
			}
			break;
		case HH_TLS_SHUTDOWN:
			if (to == HH_TLS_SHUTDOWN)
				break; // Treat this as a no-op for simplicity
			__attribute__((fallthrough));
		verybad:
		default:
#ifdef NDEBUG
			__builtin_unreachable(); // Helps the optimizer
#else
			log_fatal("You reached the unreachable (client state %d from %d), this is very bad.", to, client->state);
			log_trace();
			exit(-1);
#endif
	}
	return 0;
}

// Initiates a graceful shutdown
static int send_shutdown(struct client *client) {
	if (s2n_shutdown(client->tls, &client->blocked) < 0) {
		switch(s2n_error_get_type(s2n_errno)) {
			case S2N_ERR_T_BLOCKED:
				change_state(client, HH_TLS_SHUTDOWN);
				return 0;
			default:
				log_warn("Call to s2n_shutdown failed (%s)", s2n_strerror(s2n_errno, "EN"));
				close_client(client);
				return -1;
		}
	}
	// Graceful shutdown was successful, we can close now
	close_client(client);
	return 0;
}

static int do_negotiate(struct client *client) {
	assert(client->state == HH_NEGOTIATING_TLS);
	s2n_errno = S2N_ERR_T_OK;
	errno = 0;
	if (s2n_negotiate(client->tls, &client->blocked) < 0) {
		switch (s2n_error_get_type(s2n_errno)) {
			case S2N_ERR_T_CLOSED:
				break;
			case S2N_ERR_T_BLOCKED:
				break;
			case S2N_ERR_T_ALERT:
				log_warn("Call to s2n_negotiate gave alert %d", s2n_connection_get_alert(client->tls));
				break;
			case S2N_ERR_T_PROTO:
				log_warn("Call to s2n_negotiate returned protocol error");
				return -1;
			case S2N_ERR_T_IO:
				// I suppose if ALPN fails, then negotiate will return an error even when successful
				// Skip printing a warning if this happens, but still close the connection.
				if (errno != 0)	
					log_warn("Call to s2n_negotiate returned IO error");
				return -1;
			default:
				log_warn("Call to s2n_negotiate failed (%s)", s2n_strerror(s2n_errno, "EN"));
				return -1;
		}
	}
	return 0;
}

static int parse_frame(struct client *client, char *buf, size_t len) {
#define advance(x) ({ bufp += (x); })
#define read_u8() ({ advance(1); (uint8_t)bufp[-1]; })
#define read_u16() ({ advance(2); ntohs(bufp[-2]); })
#define read_u24() ({ advance(3); ntohs(bufp[-3]); })
#define read_u32() ({ advance(4); ntohs(bufp[-4]); })
#define remaining_len (len - (bufp - buf))
	struct ib_frame *ib = &client->ib_frame;
	char *bufp = buf;
	while (1) {
		switch (client->state) {
			case HH_WAITING_MAGIC: {
				// Parse client connection preface
				size_t read_length = MIN(remaining_len, ib->remaining);
				if (memcmp(CLIENT_MAGIC + CLIENT_MAGIC_LEN - ib->remaining,
						bufp, read_length) != 0) {
					log_warn("Invalid client connection preface");
					return -1;
				}
				ib->remaining -= read_length;
				advance(read_length);
				if (ib->remaining == 0) {
					log_debug("Parsed client connection preface");
					change_state(client, HH_WAITING_SETTINGS);
				}
				ib->remaining = H2_HEADER_SIZE;
				// Fallthrough
				__attribute__((fallthrough));
			} case HH_WAITING_SETTINGS: {
				// Parse initial SETTINGS frame
				// TODO: Unify into frame header parsing function
				size_t read_length = MIN(remaining_len, ib->remaining);
				memcpy(ib->temp_buf, bufp, read_length);
				advance(read_length);
				ib->remaining -= read_length;
				if (ib->remaining > 0)
					break;

				ib->header.length = ntohs((*(uint32_t *)ib->temp_buf) & 0xFFFFFF00);
				ib->type = ib->temp_buf[3];
				ib->header.flags = ib->temp_buf[4];
				ib->header.stream_id = ntohl(*(uint32_t*)(ib->temp_buf + 5) & 0x10000000);

				log_debug("Processed whole SETTINGS header");
				log_debug("Length: %u, type: %u, flags: %u, s_id: %u",
					ib->header.length, ib->type, ib->header.flags, ib->header.stream_id);
				if (ib->type != HH_FT_SETTINGS || (ib->header.flags & HH_SETTINGS_ACK) != 0) {
					// TODO: GOAWAY
					return -1;	
				} else
					change_state(client, HH_IDLE);
				break;
			} default:
				break;
		}

		switch (client->ib_frame.type) {
			case HH_FT_SETTINGS:
				return 0;
			default:
				return 0;
		}
	}
	log_warn("Handle loop exit better please!");
	return 0;
}

static int do_read(struct client *client) {
	#define READ_LEN 4096
	// TODO: Read in loop
	char *recv_buffer = malloc(READ_LEN);
	ssize_t nread;
	int rv = 0;
	do {
		s2n_errno = S2N_ERR_T_OK;
		if ((nread = s2n_recv(client->tls, recv_buffer, READ_LEN, &client->blocked)) < 0) {
			switch (s2n_error_get_type(s2n_errno)) {
				case S2N_ERR_T_BLOCKED:
					break;
				case S2N_ERR_T_IO:
					// TODO: Take a look at this
					perror("s2n io error");
					rv = -1;
					goto loop_end;
				default:
					fprintf(stderr, "s2n_recv: %s\n", s2n_strerror(s2n_errno, "EN"));
					rv = -1;
					goto loop_end;
			}
		} else if (nread == 0) {
			// Client disconnected, signal shutdown
			rv = -1;
			goto loop_end;
		} else {
			//write(1, recv_buffer, nread); // Debug log the data
			if (parse_frame(client, recv_buffer, (size_t)nread) < 0) {
				rv = -1;
				goto loop_end;
			}
		}
	} while (client->blocked == S2N_NOT_BLOCKED);
loop_end:
	free(recv_buffer);
	return rv;
}

static int do_write(struct client *client) {
	(void)client;
	return 0;
}

int client_on_write_ready(struct client *client) {
	switch (client->state) {
		case HH_NEGOTIATING_TLS:
			if (client->blocked == S2N_BLOCKED_ON_READ)
				break;
			if (do_negotiate(client) < 0)
				goto error;
			if (client->blocked == S2N_NOT_BLOCKED)
				change_state(client, HH_WAITING_MAGIC);
			break;
		case HH_WAITING_MAGIC:
			// TODO: Work out what to do here
			break;
		case HH_WAITING_SETTINGS:
			// Keep sending SETTINGS frame
			break;
		case HH_IDLE:
			if (do_write(client) < 0)
				goto error;
			break;
		case HH_TLS_SHUTDOWN:
			send_shutdown(client);
			break;
		default:
#ifdef NDEBUG
			__builtin_unreachable();
#else
			log_fatal("Unknown client state %d", client->state);
			exit(-1);
#endif
	} 
	return 0;
error:
	close_client(client);
	return -1;
}

int client_on_data_received(struct client *client) {
	switch (client->state) {
		case HH_NEGOTIATING_TLS:
			if (client->blocked == S2N_BLOCKED_ON_WRITE) {
				fprintf(stderr, "Unexpected data on client socket\n");
				goto error;
			}
			if (do_negotiate(client) < 0)
				goto error;
			if (client->blocked == S2N_NOT_BLOCKED)
				// Might we need to check that there is no more data available?
				change_state(client, HH_WAITING_MAGIC);
			break;
		case HH_WAITING_MAGIC:
		case HH_WAITING_SETTINGS:
		case HH_IDLE:
			if (do_read(client) < 0)
				goto error;
			break;
		case HH_TLS_SHUTDOWN:
			send_shutdown(client);
			break;
		default:	
#ifdef NDEBUG
			__builtin_unreachable();
#else
			log_fatal("Unknown client state %d", client->state);
			exit(-1);
#endif
	}

	return 0;
error:
	close_client(client);
	return -1;
}
