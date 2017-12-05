#pragma once

#include <stdint.h>

#define HH_HEADER_SIZE 9

#define HH_FT_SETTINGS 4
#define HH_FT_WINDOW_UPDATE 8
#define HH_FT_PING 6
#define HH_FT_HEADERS 1

#define HH_SETTINGS_ACK 1

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

