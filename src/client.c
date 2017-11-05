#include <stdlib.h>
#include "client.h"

struct client *client_new(int fd) {
	struct client *rv = malloc(sizeof(struct client));
	rv->tls = s2n_connection_new(S2N_SERVER);
	rv->fd = fd;
	return rv;
}

void client_free(struct client *client) {
	s2n_connection_free(client->tls);
	free(client);
}
