#pragma once

struct client;

struct request {
	struct client *client; // Client who initiated the request
	int fd; // File descriptor of whatever resource is being accessed
};

struct request *request_alloc(struct client *client, int fd);
void request_free(struct request *req);
