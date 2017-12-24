#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "frame.h"
#include "client.h"
#include "log.h"
#include "pqueue.h"

struct frame_header {
	uint8_t data[HH_HEADER_SIZE];
} __attribute__((packed));

struct frame_goaway {
	struct frame_header header;
	uint32_t last_stream;
	uint32_t err_code;
} __attribute__((packed));

struct frame_rst_stream {
	struct frame_header header;
	uint32_t err_code;
} __attribute__((packed));

struct frame_settings {
	struct frame_header header;
	struct {
		uint16_t identifier;
		uint32_t value;
	} __attribute__((packed)) fields[];
} __attribute__((packed));

struct frame_ping {
	struct frame_header header;
	uint8_t data[8];
} __attribute__((packed));

static void construct_frame_header(struct frame_header *hd, uint32_t length, uint8_t flags, uint8_t type, uint32_t stream_id) {
	hd->data[2] = length & 0xFF;
	hd->data[1] = (length >> 9) & 0xFF;
	hd->data[0] = (length >> 16) & 0xFF;
	hd->data[3] = type;
	hd->data[4] = flags;
	hd->data[8] = stream_id & 0x7F;
	hd->data[7] = (stream_id >> 8) & 0xFF;
	hd->data[6] = (stream_id >> 16) & 0xFF;
	hd->data[5] = (stream_id >> 24) & 0xFF;
}

int send_rst_stream(struct client *client, uint32_t stream_id, uint32_t err_code) {
	assert(stream_id != 0);
	struct pqueue_node *node = pqueue_node_alloc(sizeof(struct frame_rst_stream));
	struct frame_rst_stream *rst_stream = (struct frame_rst_stream *)&node->data;
	memset(rst_stream, 0, sizeof *rst_stream);
	rst_stream->err_code = htonl(err_code);
	construct_frame_header(&rst_stream->header, 4, 0, HH_FT_RST_STREAM, stream_id);
	pqueue_submit_frame(&client->pqueue, node, HH_PRI_MED);
	client_write_flush(client);
	return 0;
}

int send_goaway(struct client *client, uint32_t err_code) {
	struct pqueue_node *node = pqueue_node_alloc(sizeof(struct frame_goaway));
	struct frame_goaway *goaway = (struct frame_goaway *)&node->data;
	memset(goaway, 0, sizeof *goaway);
	if (err_code == 0)
		goaway->last_stream = htonl(0x7FFFFFFF); // High bit reserved
	else
		goaway->last_stream = htonl(client->highest_stream_seen);
	goaway->err_code = htonl(err_code);
	construct_frame_header(&goaway->header, 8, 0, HH_FT_GOAWAY, 0);
	pqueue_submit_frame(&client->pqueue, node, HH_PRI_HIGH);
	client_write_flush(client);
	return 0;
}

// Data must be 8 bytes long
int send_ping(struct client *client, uint8_t *data, bool ack) {
	struct pqueue_node *node = pqueue_node_alloc(sizeof(struct frame_ping));
	struct frame_ping *ping = (struct frame_ping *)&node->data;
	memset(ping, 0, sizeof *ping);
	memcpy(ping->data, data, 8);
	construct_frame_header(&ping->header, 8, ack, HH_FT_PING, 0);
	pqueue_submit_frame(&client->pqueue, node, HH_PRI_HIGH);
	client_write_flush(client);
	return 0;
}

// TODO: Implement sending non-empty settings frame
int send_settings(struct client *client, struct h2_settings *server_settings, bool ack) {
	(void)server_settings;
	struct pqueue_node *node = pqueue_node_alloc(sizeof(struct frame_settings));
	struct frame_settings *settings = (struct frame_settings *)&node->data;
	memset(settings, 0, sizeof *settings);
	assert(server_settings == NULL); // Not implemented yet
	construct_frame_header(&settings->header, 0, ack, HH_FT_SETTINGS, 0);
	pqueue_submit_frame(&client->pqueue, node, HH_PRI_MED);
	client_write_flush(client);
	return 0;
}
