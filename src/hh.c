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
#include "thpool.h"

#define DEFAULT_PORT "8000"
#define MAX_EVENTS 64
#define MAX_FD_QUEUE 128
#define EPOLL_THREADS 2
#define WORKER_THREADS 2
#define EVENT_CLIENT(ev) ((struct client *)(ev).data.ptr)

static volatile sig_atomic_t worker_should_quit = 0;
static volatile int fd_queue_head, fd_queue_tail;
static int fd_queue[MAX_FD_QUEUE];

static pthread_mutex_t stdout_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fd_queue_lock = PTHREAD_MUTEX_INITIALIZER;


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

static void sig_handler_quit(int signum) {
	(void)signum;
	worker_should_quit = 1;
}

static void sig_prepare(void) {
	signal(SIGTERM, sig_handler_quit);
	signal(SIGINT, sig_handler_quit);
	signal(SIGQUIT, sig_handler_quit);
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

// TODO: Signal worker thread in case it is in the middle of epoll_wait
// Returns -1 if need to drop connection
static int queue_fd(int client_fd) {
	pthread_mutex_lock(&fd_queue_lock);
	int new_head = (fd_queue_head + 1) % MAX_FD_QUEUE;
	if (new_head == fd_queue_tail) {
		// No space in queue
		pthread_mutex_unlock(&fd_queue_lock);
		return -1;
	} else {
		fd_queue[fd_queue_head] = client_fd;
		fd_queue_head = new_head;
	}
	pthread_mutex_unlock(&fd_queue_lock);
	return 0;
}


// TODO: Better load balancing, this function only consumes a single FD at a time
static void consume_available_fd(int epoll_fd) {
	if (pthread_mutex_trylock(&fd_queue_lock) == EBUSY)
		return;
	// Otherwise we now have the lock
	if (fd_queue_tail == fd_queue_head) {
		pthread_mutex_unlock(&fd_queue_lock);
		return;
	}

	// There is one or more FDs to add
	int new_fd = fd_queue[fd_queue_tail];
	fd_queue_tail = (fd_queue_tail + 1) % MAX_FD_QUEUE;
	pthread_mutex_unlock(&fd_queue_lock);

	// Add the FD to our epoll collection
	struct epoll_event event;
	event.data.ptr = client_new(new_fd);
	event.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &event) == -1) {
		perror("epoll_ctl");
	}
}

static int process_all_incoming_connections(int server_fd) {
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

		// Send FD to other threads
		if (queue_fd(client_fd) < 0) {
			fprintf(stderr, "No room in FD queue: dropping connection\n");
			close(client_fd);
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
		pthread_mutex_lock(&stdout_lock);
		int rv = write(1, buf, nread);
		pthread_mutex_unlock(&stdout_lock);
		if (rv == -1) {
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

static void worker_event_loop(void *arg) {
	(void)arg;
	int epoll_fd = epoll_create1(0);
	struct epoll_event *events = calloc(MAX_EVENTS, sizeof(struct epoll_event));

	// Event loop
	printf("Spawned worker thread\n");
	while (!worker_should_quit) {
		int n, i;
		consume_available_fd(epoll_fd);
		n = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);
		if (n < 0 && errno == EINTR)
			continue; // Need to recheck exit condition
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
			} else if (events[i].events & EPOLLIN) {
				// We have data waiting
				if (process_incoming_data(client) < 0)
					continue;
			} else {
				fprintf(stderr, "Received unknown event %d\n", events[i].events);
				continue;
			}
		}
	}
}

// Main event loop
int hh_listen(int server_fd) {
	assert(server_fd >= 0);

	struct epoll_event event;
	int rv, epoll_fd;
	(void)rv;

	if (listen(server_fd, SOMAXCONN) == -1) {
		perror("listen");
		return -1;
	}

	epoll_fd = epoll_create1(0);
	event.data.fd = server_fd;
	event.events = EPOLLIN | EPOLLET;
	// This will be the only FD we poll on the main thread
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) == -1) {
		perror("epoll_ctl");
		return -1;
	}

	// Initialise worker threads
	threadpool pool = thpool_init(EPOLL_THREADS);

	// Prepare signals
	sig_prepare();

	printf("Server waiting for connections on localhost:8000...\n");
	
	// Start worker threads TODO: don't use a thread pool for this
	for (size_t i = 0; i < EPOLL_THREADS; i++)
		thpool_add_work(pool,  worker_event_loop, NULL);

	// Event loop
	while (!worker_should_quit) {
		int n = epoll_wait(epoll_fd, &event, 1, 300);
		if (n == 0)
			continue;
		else if (n > 1) {
			fprintf(stderr, "epoll: %d events on main thread, expected 0 or 1\n", n);
			break;
		} else if (n < 0) {
			if (errno == EINTR)
				continue; // Need to recheck exit condition
			// TODO: Log error here
			fprintf(stderr, "epoll: wait error (%d)\n", n);
			break;
		}
		
		// Now we have one event, in &event
		if (event.events & EPOLLRDHUP || event.events & EPOLLHUP || event.events & EPOLLERR || !(event.events & EPOLLIN)) {
			fprintf(stderr, "Server received unexpected error %d\n", event.events);
			break;
		} else if (server_fd == event.data.fd) {
			// We have incoming connections
			if (process_all_incoming_connections(server_fd) < 0)
				return -1;
		} else {
			fprintf(stderr, "Received unknown event %d\n", event.events);
			return -1;
		}
	}

	printf("Server shutting down...\n");
	worker_should_quit = 1;
	if (close(epoll_fd) == -1)
		return -1;

	// Wait for worker threads to shut down
	thpool_destroy(pool);
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
