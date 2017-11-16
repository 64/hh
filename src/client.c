#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <s2n.h>
#include "client.h"

extern struct s2n_config *server_config;

struct client *client_new(int fd) {
	struct client *rv = malloc(sizeof(struct client));
	rv->tls = s2n_connection_new(S2N_SERVER);
	if (rv->tls == NULL) {
		fprintf(stderr, "s2n_connection_new: %s\n", s2n_strerror(s2n_errno, "EN"));
		goto cleanup; // Probably caused by mlock limits
	}
	s2n_connection_set_fd(rv->tls, fd);
	s2n_connection_set_config(rv->tls, server_config);
	s2n_connection_set_blinding(rv->tls, S2N_SELF_SERVICE_BLINDING);
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
		if (client->tls != NULL)
			s2n_connection_free(client->tls);
		free(client);
	}
}

int close_client(struct client *client) {
	int rv = close(client->fd);
	if (rv < 0)
		perror("close client");
	client_free(client);
	return rv;
}

// TODO: Use s2n's blinding when stuff fails
int client_on_write_ready(struct client *client) {
	switch (client->state) {
		case HH_NEGOTIATING_TLS:
			if (client->blocked == S2N_BLOCKED_ON_READ)
				break;
			s2n_errno = S2N_ERR_T_OK;
			if (s2n_negotiate(client->tls, &client->blocked) < 0) {
				switch (s2n_error_get_type(s2n_errno)) {
					case S2N_ERR_T_CLOSED:
					case S2N_ERR_T_BLOCKED:
						break;
					case S2N_ERR_T_ALERT:
						fprintf(stderr, "s2n_negotiate: alert: %d\n", s2n_connection_get_alert(client->tls));
						break;
					case S2N_ERR_T_PROTO:
						fprintf(stderr, "s2n_negotiate: protocol error\n");
						goto error;
					case S2N_ERR_T_IO:
						goto error;
					default:
						fprintf(stderr, "s2n_negotiate: %s\n", s2n_strerror(s2n_errno, "EN"));
						goto error;
				}
			}
			if (client->blocked == S2N_NOT_BLOCKED)
				client->state = HH_IDLE;
			break;
		case HH_IDLE:
			break;
		default:
			fprintf(stderr, "Unknown client state %d\n", client->state);
			close_client(client);
			return -1;
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
			s2n_errno = S2N_ERR_T_OK;
			if (s2n_negotiate(client->tls, &client->blocked) < 0) {
				switch (s2n_error_get_type(s2n_errno)) {
					case S2N_ERR_T_CLOSED:
					case S2N_ERR_T_BLOCKED:
						break;
					case S2N_ERR_T_ALERT:
						fprintf(stderr, "s2n_negotiate: alert: %d\n", s2n_connection_get_alert(client->tls));
						break;
					case S2N_ERR_T_PROTO:
						fprintf(stderr, "s2n_negotiate: protocol error\n");
						goto error;
					case S2N_ERR_T_IO:
						goto error;
					default:
						fprintf(stderr, "s2n_negotiate: %s\n", s2n_strerror(s2n_errno, "EN"));
						goto error;
				}
			}
			if (client->blocked == S2N_NOT_BLOCKED)
				client->state = HH_IDLE;
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
			} else {
				write(1, buf, nread);
			}
			break;
		} default:	
			fprintf(stderr, "Unknown client state %d\n", client->state);
			goto error;
			break;
	}

	return 0;
error:
	close_client(client);
	return -1;
}
