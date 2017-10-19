#include <stdio.h>
#include <sys/socket.h>
#include <signal.h>
#include <s2n.h>
#include <uv.h>

#include "hh.h"
#include "conn.h"

#define DEFAULT_BACKLOG 16

// Handles SIGINT (ctrl-C)
static void sigint_handler(uv_signal_t *handle, int signum) {
	(void)handle; (void)signum;
	uv_stop(uv_default_loop());
}

int hh_init(void) {
	int rv = 0;
	if ((rv = s2n_init()) != 0)
		return -1;
	return 0;
}

int hh_listen(void) {
	// Prepare to run, perform initialisation
	uv_loop_t *loop = uv_default_loop();

	uv_tcp_t server;
	uv_tcp_init(loop, &server);

	struct sockaddr_in addr;
	uv_ip4_addr("0.0.0.0", 8000, &addr);

	uv_tcp_bind(&server, (const struct sockaddr *)&addr, 0);
	int rv = uv_listen((uv_stream_t *)&server, DEFAULT_BACKLOG, on_new_connection);
	if (rv != 0) {
		fprintf(stderr, "Listen error %s\n", uv_strerror(rv));
		return -1;
	}

	// Setup signal handler
	uv_signal_t sig;
	uv_signal_init(loop, &sig);
	uv_signal_start_oneshot(&sig, sigint_handler, SIGINT);

	// Start listening
	uv_run(loop, UV_RUN_DEFAULT);
	return 0;
}

int hh_cleanup(void) {
	int rv = 0;
	if ((rv = s2n_cleanup()) != 0)
		return -1;
	return 0;
}
