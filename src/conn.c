#include <stdlib.h>
#include <uv.h>
#include "conn.h"

void on_new_connection(uv_stream_t *server, int status) {
	if (status < 0) {
		fprintf(stderr, "New connection error %s\n", uv_strerror(status));
		return;
	}

	uv_tcp_t *client = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(uv_default_loop(), client);
	if (uv_accept(server, (uv_stream_t *)client) == 0) {
		uv_close((uv_handle_t *)client, NULL);
	} else {
		uv_close((uv_handle_t *)client, NULL);
	}
}
