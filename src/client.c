#include <stdlib.h>
#include <stdio.h>
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
