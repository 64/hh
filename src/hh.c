#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <s2n.h>

#include "hh.h"
#include "client.h"

#define DEFAULT_PORT "8000"
#define MAX_EVENTS 64
#define EVENT_CLIENT(ev) ((struct client *)(ev).data.ptr)

static int make_fd_non_blocking(int fd) {
	int flags;
	if ((flags = fcntl(fd, F_GETFL, 0)) == -1) {
		perror("fcntl");
		return -1;
	}
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		perror("fcntl");
		return -1;
	}
	return 0;
}

static void sig_prepare(void) {
	sigset_t blocked;
	sigemptyset(&blocked);
	sigaddset(&blocked, SIGINT);
	sigaddset(&blocked, SIGTERM);
	sigaddset(&blocked, SIGQUIT);
	pthread_sigmask(SIG_BLOCK, &blocked, NULL);
	signal(SIGPIPE, SIG_IGN);
}

static bool should_quit(void) {
	sigset_t pending;
	sigpending(&pending);
	return sigismember(&pending, SIGINT) || sigismember(&pending, SIGTERM) || sigismember(&pending, SIGQUIT); 
}

int hh_init(void) {
	int rv = 0;
	int server_fd, yes = 1;
	struct addrinfo hints, *servinfo, *p;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ((rv = getaddrinfo(NULL, DEFAULT_PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return -1;
	}

	// Bind to the first available
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((server_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}

		if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("setsockopt");
			return -1;
		}

		if (bind(server_fd, p->ai_addr, p->ai_addrlen) == -1) {
			close(server_fd);
			perror("bind");
			continue;
		}

		if (make_fd_non_blocking(server_fd) == -1)
			return -1;

		break;
	}	

	freeaddrinfo(servinfo);

	if (p == NULL) {
		fprintf(stderr, "bind: failed\n");
		return -1;
	}

	// Initialise s2n
	if ((rv = s2n_init()) != 0) {
		fprintf(stderr, "s2n_init: failed\n");
		return -1;
	}
	
	return server_fd;
}

static int process_all_incoming_connections(int epoll_fd, int server_fd) {
	struct epoll_event event;
	while (1) {
		struct sockaddr in_addr;
		socklen_t in_len;
		int client_fd;
		char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

		in_len = sizeof in_addr;
		client_fd = accept4(server_fd, &in_addr, &in_len, SOCK_NONBLOCK);
		if (client_fd == -1) {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
				break; // Processed all connections
			else {
				perror("accept");
				break;
			}
		}

		if (getnameinfo(&in_addr, in_len, hbuf, sizeof hbuf, 
			sbuf, sizeof sbuf, NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
			printf("Accepted connection on descriptor %d "
				"(host = %s, port = %s)\n", client_fd, hbuf, sbuf);
		}

		event.data.ptr = client_new(client_fd);
		event.events = EPOLLIN | EPOLLET;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) == -1) {
			perror("epoll_ctl");
			return -1;
		}
	}

	return 0;
}

static int close_client(struct client *client) {
	client_free(client);
	return close(client->fd);
}

static int process_incoming_data(struct client *client) {
	bool done = false;
	int fd = client->fd;
	while (1) {
		ssize_t nread;
		char buf[512];

		nread = read(fd, buf, sizeof buf);
		if (nread == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				perror("read");
				done = true;
			}
			break;
		} else if (nread == 0) {
			done = true;
			break;
		}

		// Ready to read
		if (write(1, buf, nread) == -1) {
			perror("write");
			return -1;
		}
	}

	if (done) {
		printf("Closed connection on descriptor %d\n", fd);
		if (close_client(client) != 0)
			return -1;
	}

	return 0;
}

// Main event loop
int hh_listen(int server_fd) {
	assert(server_fd >= 0);

	struct epoll_event event;
	struct epoll_event *events;
	int rv, epoll_fd;
	(void)rv;

	if (listen(server_fd, SOMAXCONN) == -1) {
		perror("listen");
		return -1;
	}

	epoll_fd = epoll_create1(0);
	// Works since fd is the first member of struct client
	event.data.ptr = &server_fd;
	event.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) == -1) {
		perror("epoll_ctl");
		return -1;
	}

	events = calloc(MAX_EVENTS, sizeof event);

	// Prepare signals
	sig_prepare();

	// Event loop
	printf("Server waiting for connections on localhost:8000...\n");
	while (!should_quit()) {
		int n, i;
		n = epoll_wait(epoll_fd, events, MAX_EVENTS, 300);
		for (i = 0; i < n; i++) {
			struct client *client = EVENT_CLIENT(events[i]);
			if (events[i].events & EPOLLRDHUP) {
				fprintf(stderr, "client disconnected via EPOLLRDHUP\n");
				close_client(client);
			} else if (events[i].events & EPOLLHUP) {
				fprintf(stderr, "client disconnected via EPOLLHUP\n");
				close_client(client);
			} else if (events[i].events & EPOLLERR) {
				fprintf(stderr, "epoll error (flags %d)\n", events[i].events);
				close_client(client);
			} else if (server_fd == client->fd) {
				// We have incoming connections
				if (process_all_incoming_connections(epoll_fd, server_fd) < 0)
					return -1;
			} else if (events[i].events & EPOLLIN) {
				// We have data waiting
				if (process_incoming_data(client) < 0)
					return -1;
			} else {
				fprintf(stderr, "Received unknown event %d\n", events[i].events);
				return -1;
			}
		}
	}

	printf("Server shutting down...\n");

	if (close(epoll_fd) == -1)
		return -1;

	return 0;
}

int hh_cleanup(int server_fd) {
	int rv = 0;
	if (close(server_fd) == -1)
		return -1;
	if ((rv = s2n_cleanup()) != 0)
		return -1;
	return 0;
}
