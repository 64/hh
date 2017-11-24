#pragma once

#include <stdint.h>

#define H2_HEADER_SIZE 9

#define HH_FT_SETTINGS 4

#define HH_SETTINGS_ACK 1

struct h2_frame_hd {
	uint32_t length; // 24 bits
	uint8_t flags;
	uint32_t stream_id; // 31 bits
};

struct ib_frame {
	uint8_t type;
	size_t remaining;
	char temp_buf[H2_HEADER_SIZE];
	struct h2_frame_hd header;
};

