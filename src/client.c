#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <s2n.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "client.h"
#include "log.h"

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
				case HH_SHUTTING_DOWN:
					client->state = to;
					break;
				default:
					goto verybad;
			}
			break;
		case HH_NEGOTIATING_TLS:
			switch (to) {
				case HH_IDLE:
					client->state = to;
					break;
				default:
					goto verybad;
			}
			break;
		case HH_SHUTTING_DOWN:
			if (to == HH_SHUTTING_DOWN)
				break; // Treat this as a no-op for simplicity
			__attribute__((fallthrough));
		verybad:
		default:
#ifdef NDEBUG
			__builtin_unreachable(); // Helps the optimizer
#else
			log_fatal("You reached the unreachable, this is very bad.");
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
				change_state(client, HH_SHUTTING_DOWN);
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

int client_on_write_ready(struct client *client) {
	switch (client->state) {
		case HH_NEGOTIATING_TLS:
			if (client->blocked == S2N_BLOCKED_ON_READ)
				break;
			if (do_negotiate(client) < 0)
				goto error;
			if (client->blocked == S2N_NOT_BLOCKED)
				change_state(client, HH_IDLE);
			break;
		case HH_IDLE:
			break;
		case HH_SHUTTING_DOWN:
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
				change_state(client, HH_IDLE);
			break;
		case HH_IDLE: {
			char buf[1024];
			ssize_t nread;
			s2n_errno = S2N_ERR_T_OK;
			if ((nread = s2n_recv(client->tls, buf, 1024, &client->blocked)) < 0) {
				switch (s2n_error_get_type(s2n_errno)) {
					case S2N_ERR_T_BLOCKED:
						break;
					default:
						fprintf(stderr, "s2n_recv: %s\n", s2n_strerror(s2n_errno, "EN"));
						goto error;
				}
			} else if (nread == 0) {
				// Client disconnected
				close_client(client);
			} else {
				write(1, buf, nread);
			}
			break;
		} case HH_SHUTTING_DOWN:
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
