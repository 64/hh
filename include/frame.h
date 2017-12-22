#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define HH_HEADER_SIZE 9

// Frame types
#define HH_FT_HEADERS 1
#define HH_FT_RST_STREAM 3
#define HH_FT_SETTINGS 4
#define HH_FT_PING 6
#define HH_FT_GOAWAY 7
#define HH_FT_WINDOW_UPDATE 8
#define HH_FT_CONTINUATION 9

// Frame flags
#define HH_SETTINGS_ACK 1
#define HH_PING_ACK 1
#define HH_HEADERS_END_STREAM 1
#define HH_HEADERS_END_HEADERS 4
#define HH_PADDED 8
#define HH_PRIORITY 32

// Error types
#define HH_ERR_NONE 0
#define HH_ERR_PROTOCOL 1
#define HH_ERR_INTERNAL 2
#define HH_ERR_FLOW_CONTROL 3
#define HH_ERR_SETTINGS_TIMEOUT 4
#define HH_ERR_STREAM_CLOSED 5
#define HH_ERR_FRAME_SIZE 6
#define HH_ERR_REFUSED_STREAM 7
#define HH_ERR_CANCEL 8
#define HH_ERR_COMPRESSION 9
#define HH_ERR_CONNECT 10
#define HH_ERR_EHNANCE_YOUR_CALM 11 // c|:^)
#define HH_ERR_INADEQUATE_SECURITY 12

struct h2_frame_hd {
	uint32_t length; // 24 bits
	uint8_t type;
	uint8_t flags;
	uint32_t stream_id; // 31 bits
};

struct ib_frame {
	size_t remaining;
	char temp_buf[HH_HEADER_SIZE];
	struct h2_frame_hd header;
	char *payload;
	enum {
		HH_FRAME_HD,
		HH_FRAME_PAYLOAD,
	} state;
};

struct client;
struct h2_settings;

int send_goaway(struct client *, uint32_t);
int send_ping(struct client *client, uint8_t *data, bool ack);
int send_settings(struct client *client, struct h2_settings *server_settings, bool ack);
