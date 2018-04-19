#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <s2n.h>

#include "client.h"
#include "log.h"
#include "util.h"

#define DEFAULT_PORT 8000
#define MAX_EVENTS 64
#define MAX_FD_QUEUE 256
#ifndef WORKER_THREADS
#define WORKER_THREADS 4
#endif

static volatile int fd_queue_head, fd_queue_tail;
static int signal_fd, fd_queue[MAX_FD_QUEUE];

static pthread_mutex_t fd_queue_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *certificate_path = "data/cert.pem";
static const char *pkey_path = "data/pkey.pem";

struct s2n_config *server_config;

static void sig_prepare(void) {
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGQUIT);
	signal_fd = signalfd(-1, &sigset, SFD_NONBLOCK);
	if (signal_fd < 0)
		exit(-1);

	sigaddset(&sigset, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);
}

static int load_server_cert(void) {
	server_config = s2n_config_new();
	if (server_config == NULL) {
		log_fatal("Failed to allocate s2n server config (check mlock permissions)");
		return -1;
	}

	// Set config and cipher suite preferences
	if (s2n_config_set_cipher_preferences(server_config, "h2") < 0) {
		log_fatal("Cannot find 'h2' cipher suite: you may need to apply a custom patch to s2n.");
		return -1;
	}

	// Set ALPN to negotiate h2 (HTTP/2) protocol
	const char *proto_name = "h2";
	if (s2n_config_set_protocol_preferences(server_config, &proto_name, 1) < 0) {
		log_fatal("Cannot set ALPN identifier to 'h2' (%s)", s2n_strerror(s2n_errno, "EN"));
		return -1;
	}

	FILE *cert_file = fopen(certificate_path, "r");
	FILE *pkey_file = fopen(pkey_path, "r");
	if (cert_file == NULL) {
		log_fatal("Call to fopen on certificate file failed (%s)", strerror(errno));
		return -1;
	} else if (pkey_file == NULL) {
		log_fatal("Call to fopen on private key file failed (%s)", strerror(errno));
		return -1;
	}

	// TODO: Don't leak on early return
	// Read certificate file into buffer
	fseek(cert_file, 0, SEEK_END);
	long cert_size = ftell(cert_file);
	fseek(cert_file, 0, SEEK_SET);
	char *cert_data = malloc(cert_size + 1);
	if (fread(cert_data, cert_size, 1, cert_file) != 1) {
		log_fatal("Call to fread on certificate file failed");
		return -1;
	}
	cert_data[cert_size] = '\0';

	// Read private key file into buffer
	fseek(pkey_file, 0, SEEK_END);
	long pkey_size = ftell(pkey_file);
	fseek(pkey_file, 0, SEEK_SET);
	char *pkey_data = malloc(pkey_size + 1);
	if (fread(pkey_data, pkey_size, 1, pkey_file) != 1) {
		log_fatal("Call to fread on private key file failed");
		return -1;
	}
	pkey_data[pkey_size] = '\0';

	if (s2n_config_add_cert_chain_and_key(server_config, cert_data, pkey_data) != 0) {
		log_fatal("Failed to add certificate/key to s2n (%s)", s2n_strerror(s2n_errno, "EN"));
		return -1;
	} else
		log_info("Successfully loaded certificate and private key file");

	free(cert_data);
	free(pkey_data);
	fclose(cert_file);
	fclose(pkey_file);
	return 0;
}

// Returns -1 if need to drop connection
static int queue_fd(int event_fd, int client_fd) {
	pthread_mutex_lock(&fd_queue_lock);
	int new_head = (fd_queue_head + 1) % MAX_FD_QUEUE;
	if (new_head == fd_queue_tail) {
		// No space in queue
		pthread_mutex_unlock(&fd_queue_lock);
		return -1;
	} else {
		log_debug("Queued FD at %d", fd_queue_head);
		fd_queue[fd_queue_head] = client_fd;
		fd_queue_head = new_head;
	}
	pthread_mutex_unlock(&fd_queue_lock);

	// Signal that we added one connection to the queue (wakes up epoll watchers)
	uint64_t val = 1;
	if (write(event_fd, &val, sizeof val) == -1 && errno == EINVAL) {
		log_fatal("Call to write(event_fd) failed (%s)", strerror(errno));
		exit(-1);
	}
	return 0;
}

// TODO: Better load balancing - may need to rework this with one queue per thread
static void consume_available_fd(int epoll_fd) {
	pthread_mutex_lock(&fd_queue_lock);
	// Otherwise we now have the lock
	if (fd_queue_tail != fd_queue_head) {
		// Grab the FD from the queue
		int new_fd = fd_queue[fd_queue_tail];
		log_debug("Consumed FD at position %d", fd_queue_tail);
		fd_queue_tail = (fd_queue_tail + 1) % MAX_FD_QUEUE;
		pthread_mutex_unlock(&fd_queue_lock);

		// Initialise per-client timer
		int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
		if (timer_fd < 0) {
			log_warn("Call to timerfd_create failed (%s)", strerror(errno));
			close(new_fd);
			return;
		}

		// Add the FDs to our epoll collection
		struct epoll_event event;
		event.data.ptr = client_new(new_fd, timer_fd); // Might fail due to mlock limits
		if (event.data.ptr == NULL) {
			log_warn("Call to client_new failed");
			close(new_fd);
			close(timer_fd);
			return;
		}

		event.events = CLIENT_EPOLL_EVENTS;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &event) == -1) {
			log_warn("FD: %d", new_fd);
			log_warn("Call to epoll_ctl on socket fd failed (%s)", strerror(errno));
			client_free(event.data.ptr);
			return;
		}

		// Little hack: if bit 0 of ptr is set, timer event was fired.
		// Otherwise an event was fired for the actual socket FD.
		assert(((uintptr_t)event.data.ptr & 1) == 0);
		event.data.ptr = (void *)((uintptr_t)event.data.ptr + 1);
		event.events = EPOLLIN | EPOLLET;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &event) == -1) {
			log_warn("FD: %d", timer_fd);
			log_warn("Call to epoll_ctl on timer fd failed (%s)", strerror(errno));
			client_free(event.data.ptr);
			return;
		}
	} else
		pthread_mutex_unlock(&fd_queue_lock);
}

static int process_all_incoming_connections(int *event_fds, int server_fd) {
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
				log_warn("Call to accept failed (%s)", strerror(errno));
				break;
			}
		}

		int flag = 1;
		if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof (int)) < 0) {
			log_warn("Call to setsockopt(TCP_NODELAY) failed (%s)", strerror(errno));
			close(client_fd);
			break;
		}

		// Send FD to other threads
		static sig_atomic_t next_thread = 0;
		if (queue_fd(event_fds[next_thread], client_fd) < 0) {
			log_warn("No room in FD queue: dropping connection");
			close(client_fd);
		}
		// Wraparound to first thread
		if (++next_thread == WORKER_THREADS)
			next_thread = 0;
	}

	return 0;
}

static void *worker_event_loop(void *state) {
	struct thread_state *ts = (struct thread_state *)state;
	int epoll_fd = epoll_create1(0);
	ts->epoll_fd = epoll_fd;
	struct epoll_event *events = calloc(MAX_EVENTS, sizeof(struct epoll_event));

	int event_fd = ts->event_fd;
	events[0].data.ptr = &event_fd;
	events[0].events = EPOLLIN | EPOLLET;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event_fd, &events[0]) == -1) {
		log_fatal("Call to epoll_ctl failed (%s)", strerror(errno));
		return NULL;
	}

	set_thread_state(state);
	free(state);

	// Add the signal_fd to our set to epoll
	events[0].data.ptr = &signal_fd;
	events[0].events = EPOLLIN | EPOLLET;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, signal_fd, &events[0]) == -1) {
		log_fatal("Call to epoll_ctl failed (%s)", strerror(errno));
		return NULL;
	}

	// Event loop
	log_debug("Spawned worker thread");
	int should_exit = 0;
	while (!should_exit) {
		int n, i;
		n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
		if (n < 0 && errno == EINTR)
			continue; // Need to recheck exit condition
		for (i = 0; i < n; i++) {
			// If the last bit of the pointer is set, the timer and not the socket is ready to use
			bool timer_expired = (uintptr_t)(events[i].data.ptr) & 1;
			struct client *client = (struct client *)((uintptr_t)events[i].data.ptr & ~1);
			if (events[i].events & EPOLLRDHUP) {
				client_close_immediate(client);
				continue;
			} else if (events[i].events & EPOLLHUP) {
				client_close_immediate(client);
				continue;
			} else if (events[i].events & EPOLLERR) {
				if (!timer_expired && client->fd != event_fd && client->fd != signal_fd) {
					int error = 0;
					socklen_t errlen = sizeof(error);
					if (getsockopt(client->fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen) == 0) {
						log_warn("Epoll event error (%s: flags %d)", strerror(error), events[i].events);
					} else
						log_warn("Epoll event error on socket (flags %d)", events[i].events);
				} else
					log_warn("Epoll event error (flags %d)", events[i].events);
				client_close_immediate(client);
				continue;
			}
			if (events[i].events & EPOLLIN) {
				if (client->fd == event_fd) {
					uint64_t efd_read;
					if (read(event_fd, &efd_read, sizeof efd_read) > 0)
						consume_available_fd(epoll_fd);
					continue;
				} else if (timer_expired) {
					if (client_on_timer_expired(client) < 0) {
						client_close_immediate(client);
					}
					continue;
				} else if (client->fd == signal_fd) {
					should_exit = 1; // Maybe we should check which signal?
					break;
				} else if (client_on_data_received(client) < 0) {
					continue; // Client has been immediately closed
				}
			}
			if (events[i].events & EPOLLOUT || client_pending_write(client)) {
				if (client_on_write_ready(client) < 0) {
					continue; // Client has been immediately closed
				}
			}
			if (client->is_closing) {
				if (client_close_graceful(client) < 0) {
					client_close_immediate(client);
				}
			}
		}
	}

	// TODO: Call s2n_cleanup here

	free(events);
	return NULL;
}

static int server_init(unsigned short port) {
	int server_fd, yes = 1, rv = 0;
	struct addrinfo hints, *servinfo, *p;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	char port_buf[6];
	snprintf(port_buf, 6, "%hu", port);

	if ((rv = getaddrinfo(NULL, port_buf, &hints, &servinfo)) != 0) {
		log_fatal("Call to getaddrinfo failed (%s)", gai_strerror(rv));
		return -1;
	}

	// Bind to the first available
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((server_fd = socket(p->ai_family, p->ai_socktype | SOCK_NONBLOCK, p->ai_protocol)) == -1) {
			log_warn("Call to socket failed (%s)", strerror(errno));
			continue;
		}

		if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			log_warn("Call to setsockopt failed (%s)", strerror(errno));
			return -1;
		}

		if (bind(server_fd, p->ai_addr, p->ai_addrlen) == -1) {
			close(server_fd);
			log_warn("Call to bind failed (%s)", strerror(errno));
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo);

	if (p == NULL) {
		log_fatal("Could not bind to any available socket");
		return -1;
	}

	// Initialise s2n
	if ((rv = s2n_init()) != 0) {
		log_fatal("Call to s2n_init failed (%s)", s2n_strerror(s2n_errno, "EN"));
		return -1;
	}

	if (load_server_cert() != 0) {
		log_fatal("Failed to load server certificate and private key file");
		return -1;
	}

	return server_fd;
}

static int server_listen(int server_fd, unsigned short port) {
	assert(server_fd >= 0);

	if (listen(server_fd, SOMAXCONN) == -1) {
		log_fatal("Call to listen failed (%s)", strerror(errno));
		return -1;
	}

	int epoll_fd = epoll_create1(0);
	struct epoll_event event;
	memset(&event, 0, sizeof event);
	event.data.fd = server_fd;
	event.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) == -1) {
		log_fatal("Call to epoll_ctl failed (%s)", strerror(errno));
		return -1;
	}

	// Prepare signals
	sig_prepare();
	event.data.fd = signal_fd;
	event.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, signal_fd, &event) == -1) {
		log_fatal("Call to epoll_ctl failed (%s)", strerror(errno));
		return -1;
	}

	// Initialise eventfds (one per worker thread)
	int *event_fds = malloc(sizeof(int) * WORKER_THREADS);
	for (size_t i = 0; i < WORKER_THREADS; i++) {
		event_fds[i] = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE);
	}

	log_info("Server waiting for connections on localhost:%hu...", port);

	// Start worker threads
	pthread_t worker_threads[WORKER_THREADS];
	for (size_t i = 0; i < WORKER_THREADS; i++) {
		struct thread_state *state = malloc(sizeof *state);
		state->event_fd = event_fds[i];
		state->epoll_fd = -1;
		if ((errno = pthread_create(&worker_threads[i], NULL, worker_event_loop, state)) != 0) {
			log_fatal("Call to pthread_create failed (%s)", strerror(errno));
			free(event_fds);
			return -1;
		}
	}


	// Event loop
	while (1) {
		int n = epoll_wait(epoll_fd, &event, 1, -1);
		if (n == 0)
			continue;
		else if (n < 0) {
			if (errno == EINTR)
				continue; // Need to recheck exit condition
			log_fatal("Call to epoll_wait failed (%s)", strerror(errno));
			break;
		}

		// Now we have one event, in &event
		if (event.data.fd == signal_fd) {
			break;
		} else if (event.events & EPOLLRDHUP || event.events & EPOLLHUP || event.events & EPOLLERR || !(event.events & EPOLLIN)) {
			log_fatal("Epoll event error (flags %d)", event.events);
			break;
		} else if (server_fd == event.data.fd) {
			// We have incoming connections
			if (process_all_incoming_connections(event_fds, server_fd) < 0)
				return -1;
		} else {
			log_warn("Epoll event unknown (%d)", event.events);
			return -1;
		}
	}

	log_info("Server shutting down...");
	if (close(epoll_fd) == -1) {
		log_fatal("Call to close(epoll_fd) failed (%s)", strerror(errno));
		return -1;
	}

	// Wait for worker threads to shut down
	for (size_t i = 0; i < WORKER_THREADS; i++) {
		if ((errno = pthread_join(worker_threads[i], NULL)) != 0) {
			log_fatal("Call to pthread_join failed (%s)", strerror(errno));
			return -1;
		}
		if (close(event_fds[i]) == -1) {
			log_fatal("Failed to close eventfd of thread %zu (%s)", i, strerror(errno));
			return -1;
		}
	}

	free(event_fds);

	if (close(signal_fd) == -1) {
		log_fatal("Call to close(signal_fd) failed (%s)", strerror(errno));
		return -1;
	}

	return 0;
}

static int server_cleanup(int server_fd) {
	int rv = 0;
	if (close(server_fd) == -1) {
		log_fatal("Call to close(server_fd) failed (%s)", strerror(errno));
		return -1;
	}
	s2n_config_free(server_config);
	if ((rv = s2n_cleanup()) != 0) {
		log_fatal("Call to s2n_cleanup on main thread failed (%s)", s2n_strerror(s2n_errno, "EN"));
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[]) {
	int fd;
	// Parse port number from command line option
	unsigned short port_num = DEFAULT_PORT;
	if (argc > 2) {
		log_fatal("Usage: hh [port]");
		return -1;
	} else if (argc == 2) {
		char *endptr;
		long temp = strtoul(argv[1], &endptr, 10);
		if (*endptr != '\0' || temp > USHRT_MAX) {
			log_fatal("Invalid port number '%s'.", argv[1]);
			return -1;
		} else
			port_num = (unsigned short)temp;
	}
	if ((fd = server_init(port_num)) < 0)
		return -1;
	else if (server_listen(fd, port_num) < 0)
		return -1;
	else if (server_cleanup(fd) < 0)
		return -1;
	return 0;
}

