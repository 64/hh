#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <s2n.h>

#include "hh.h"
#include "client.h"
#include "thpool.h"

#define DEFAULT_PORT "8000"
#define MAX_EVENTS 64
#define MAX_FD_QUEUE 256
#define EPOLL_THREADS 3
#define EVENT_CLIENT(ev) ((struct client *)(ev).data.ptr)

static volatile sig_atomic_t worker_should_quit = 0;
static int fd_queue_head, fd_queue_tail;
static int fd_queue[MAX_FD_QUEUE];

static pthread_mutex_t fd_queue_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *certificate_path = "test/cert.pem";
static const char *pkey_path = "test/pkey.pem";

struct s2n_config *server_config;

static void sig_handler_quit(int signum) {
	(void)signum;
	worker_should_quit = 1;
}

static void sig_prepare(void) {
	signal(SIGTERM, sig_handler_quit);
	signal(SIGINT, sig_handler_quit);
	signal(SIGQUIT, sig_handler_quit);
	signal(SIGPIPE, SIG_IGN); // Ignore this because it would make us crash
}

static int load_server_cert(void) {
	server_config = s2n_config_new();
	if (server_config == NULL) {
		fprintf(stderr, "Failed to allocate s2n server config (check mlock permissions)\n");
		return -1;
	}

	FILE *cert_file = fopen(certificate_path, "r");
	FILE *pkey_file = fopen(pkey_path, "r");
	if (cert_file == NULL) {
		perror("fopen on cert file");
		return -1;
	} else if (pkey_file == NULL) {
		perror("fopen on pkey file");
		return -1;
	}

	// Read certificate file into buffer
	fseek(cert_file, 0, SEEK_END);
	long cert_size = ftell(cert_file);
	fseek(cert_file, 0, SEEK_SET);
	char *cert_data = malloc(cert_size + 1);
	fread(cert_data, cert_size, 1, cert_file);
	cert_data[cert_size] = '\0';

	// Read private key file into buffer
	fseek(pkey_file, 0, SEEK_END);
	long pkey_size = ftell(pkey_file);
	fseek(pkey_file, 0, SEEK_SET);
	char *pkey_data = malloc(pkey_size + 1);
	fread(pkey_data, pkey_size, 1, pkey_file);
	pkey_data[pkey_size] = '\0';

	if (s2n_config_add_cert_chain_and_key(server_config, cert_data, pkey_data) != 0) {
		fprintf(stderr, "%s\n", s2n_strerror(s2n_errno, "EN"));
		return -1;
	} else
		printf("Successfully loaded certificate and private key file\n");

	free(cert_data);
	free(pkey_data);
	return 0;
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
		if ((server_fd = socket(p->ai_family, p->ai_socktype | SOCK_NONBLOCK, p->ai_protocol)) == -1) {
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

	if (load_server_cert() != 0)
		return -1;
	
	return server_fd;
}

static int close_client(struct client *client) {
	int rv = close(client->fd);
	if (rv < 0)
		perror("close client");
	client_free(client);
	return rv;
}

// TODO: Signal worker thread in case it is in the middle of epoll_wait
// Returns -1 if need to drop connection
static int queue_fd(int event_fd, int client_fd) {
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

	// Signal we added one connection to the queue
	uint64_t val = 1;
	write(event_fd, &val, sizeof val);
	return 0;
}

// TODO: Better load balancing - need to rework this with one eventfd per thread
static void consume_available_fd(int epoll_fd) {
	pthread_mutex_lock(&fd_queue_lock);
	// Otherwise we now have the lock
	if (fd_queue_tail != fd_queue_head) {
		// Grab the FD from the queue
		int new_fd = fd_queue[fd_queue_tail];
		fd_queue_tail = (fd_queue_tail + 1) % MAX_FD_QUEUE;
		pthread_mutex_unlock(&fd_queue_lock);

		// Add the FD to our epoll collection
		struct epoll_event event;
		event.data.ptr = client_new(new_fd);
		// Might fail due to mlock limits
		if (event.data.ptr == NULL) {
			close(new_fd);
			return;

		}
		event.events = EPOLLIN | EPOLLOUT | EPOLLET;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &event) == -1) {
			perror("epoll_ctl");
		}
	} else
		pthread_mutex_unlock(&fd_queue_lock);
}

static int process_all_incoming_connections(int event_fd, int server_fd) {
	while (1) {
		struct sockaddr in_addr;
		socklen_t in_len;
		int client_fd;

		in_len = sizeof in_addr;
		client_fd = accept4(server_fd, &in_addr, &in_len, SOCK_NONBLOCK);
		if (client_fd == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break; // Processed all connections
			else {
				perror("accept");
				break;
			}
		}

		// Send FD to other threads
		if (queue_fd(event_fd, client_fd) < 0) {
			fprintf(stderr, "No room in FD queue: dropping connection\n");
			close(client_fd);
		}
	}

	return 0;
}

static int process_incoming_data(struct client *client) {
	bool done = false;
	switch (client->state) {
		case HH_NEGOTIATING_TLS:
			if (client->blocked == S2N_BLOCKED_ON_WRITE) {
				fprintf(stderr, "Unexpected data on client socket\n");
				goto error;
			}
			s2n_errno = S2N_ERR_T_OK;
			if (s2n_negotiate(client->tls, &client->blocked) < 0) {
				switch (s2n_error_get_type(s2n_errno)) {
					case S2N_ERR_T_BLOCKED:
						break;
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

static int send_outgoing_data(struct client *client) {
	switch (client->state) {
		case HH_NEGOTIATING_TLS:
			if (client->blocked == S2N_BLOCKED_ON_READ)
				break;
			s2n_errno = S2N_ERR_T_OK;
			if (s2n_negotiate(client->tls, &client->blocked) < 0) {
				switch (s2n_error_get_type(s2n_errno)) {
					case S2N_ERR_T_BLOCKED:
						break;
					default:
						fprintf(stderr, "s2n_negotiate: %s\n", s2n_strerror(s2n_errno, "EN"));
						close_client(client);
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
	} while (client->blocked != S2N_NOT_BLOCKED);
	return 0;
}

static void *worker_event_loop(void *arg) {
	int epoll_fd = epoll_create1(0);
	struct epoll_event *events = calloc(MAX_EVENTS, sizeof(struct epoll_event));

	int event_fd = *(int *)arg; // Points to the eventfd - works since FD is first in struct
	events[0].data.ptr = &event_fd; 
	events[0].events = EPOLLIN | EPOLLET;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event_fd, &events[0]) == -1) {
		perror("epoll_ctl");
	}

	// Event loop
	printf("Spawned worker thread\n");
	while (!worker_should_quit) {
		int n, i;
		n = epoll_wait(epoll_fd, events, MAX_EVENTS, 500);
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
				if (client->fd == event_fd) {
					uint64_t efd_read;
					if (read(event_fd, &efd_read, sizeof efd_read) > 0)
						consume_available_fd(epoll_fd);
				} else if (process_incoming_data(client) < 0) {
					fprintf(stderr, "Failed to read incoming data\n");
					break;
				}
			} else if (events[i].events & EPOLLOUT) {
				if (send_outgoing_data(client) < 0) {
					fprintf(stderr, "Failed to send outgoing data\n");
					break;
				}
			} else {
				fprintf(stderr, "Received unknown event %d\n", events[i].events);
				continue;
			}
		}
	}

	free(events);
	return NULL;
}

// Main event loop
int hh_listen(int server_fd) {
	assert(server_fd >= 0);

	struct epoll_event event;
	int epoll_fd, event_fd;

	if (listen(server_fd, SOMAXCONN) == -1) {
		perror("listen");
		return -1;
	}

	epoll_fd = epoll_create1(0);
	memset(&event, 0, sizeof event);
	event.data.fd = server_fd;
	event.events = EPOLLIN | EPOLLET;
	// This will be the only FD we poll on the main thread
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) == -1) {
		perror("epoll_ctl");
		return -1;
	}

	// Initialise eventfd
	event_fd = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE);

	// Prepare signals
	sig_prepare();

	printf("Server waiting for connections on localhost:8000...\n");
	
	// Start worker threads
	pthread_t worker_threads[EPOLL_THREADS];
	for (size_t i = 0; i < EPOLL_THREADS; i++) {
		if ((errno = pthread_create(&worker_threads[i], NULL, worker_event_loop, &event_fd)) != 0) {
			perror("pthread_create");
			return -1;
		}
	}


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
			if (process_all_incoming_connections(event_fd, server_fd) < 0)
				return -1;
		} else {
			fprintf(stderr, "Received unknown event %d\n", event.events);
			return -1;
		}
	}

	printf("Server shutting down...\n");
	if (close(epoll_fd) == -1)
		return -1;

	// Wait for worker threads to shut down
	worker_should_quit = 1;
	for (size_t i = 0; i < EPOLL_THREADS; i++) {
		if ((errno = pthread_join(worker_threads[i], NULL)) != 0) {
			perror("pthread_join");
			return -1;
		}
	}

	if (close(event_fd) == -1)
		return -1;

	return 0;
}

int hh_cleanup(int server_fd) {
	int rv = 0;
	if (close(server_fd) == -1)
		return -1;
	s2n_config_free(server_config);
	if ((rv = s2n_cleanup()) != 0)
		return -1;
	return 0;
}
