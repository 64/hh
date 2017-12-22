#include <stdlib.h>
#include "request.h"

struct request *request_alloc(struct client *client, int fd) {
	struct request *rv = malloc(sizeof *rv);
	rv->client = client;
	rv->fd = fd;
	return rv;
}

void request_free(struct request *req) {
	free(req);
}
