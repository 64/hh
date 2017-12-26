#pragma once

#include <stddef.h>
#include <stdint.h>

// TODO: Make this safer
#define MIN(x, y) ((x) > (y) ? (y) : (x))

struct thread_state {
	int event_fd;
	int epoll_fd;
};
