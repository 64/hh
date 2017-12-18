#include <arpa/inet.h>
#include <stdint.h>
#include <assert.h>

#include "frame.h"
#include "client.h"
#include "log.h"

struct frame_header {
	uint8_t data[HH_HEADER_SIZE];
} __attribute__((packed));

struct frame_goaway {
	struct frame_header header;
	uint32_t last_stream;
	uint32_t err_code;
} __attribute__((packed));

struct frame_settings {
	struct frame_header header;
	struct {
		uint16_t identifier;
		uint32_t value;
	} __attribute__((packed)) fields[];
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

int send_goaway(struct client *client, uint32_t err_code) {
	struct frame_goaway goaway = { 0 };
	if (err_code == 0)
		goaway.last_stream = htonl(0x7FFFFFFF); // High bit reserved
	// TODO: else ...
	goaway.err_code = htonl(err_code);
	construct_frame_header(&goaway.header, 8, 0, HH_FT_GOAWAY, 0);
	client_queue_write(client, (char *)&goaway, sizeof goaway);
	return 0;
}

// TODO: Implement sending non-empty settings frame
int send_settings(struct client *client, struct h2_settings *server_settings, bool ack) {
	(void)server_settings;
	struct frame_settings settings = { 0 };
	assert(server_settings == NULL);
	construct_frame_header(&settings.header, 0, ack, HH_FT_SETTINGS, 0);
	client_queue_write(client, (char *)&settings, sizeof settings);
	return 0;
}
