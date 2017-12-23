#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <s2n.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>

#include "client.h"
#include "buf_chain.h"
#include "log.h"
#include "util.h"

#define CLIENT_MAGIC "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define CLIENT_MAGIC_LEN 24

extern struct s2n_config *server_config;

_Thread_local int epoll_fd = -1;

struct h2_settings default_settings = {
	.header_table_size = 4096,
	.enable_push = 1,
	.max_concurrent_streams = 1,
	.initial_window_size = 65535,
	.max_frame_size = 16384,
	.max_header_list_size = 0xFFFFFFFF
};

struct client *client_new(int fd, int timer_fd, int efd) {
	epoll_fd = efd;
	struct client *rv = malloc(sizeof(struct client));
	rv->tls = s2n_connection_new(S2N_SERVER);
	if (rv->tls == NULL) {
		log_warn("Call to s2n_connection_new failed (%s)", s2n_strerror(s2n_errno, "EN"));
		goto cleanup; // Probably caused by mlock limits
	}
	s2n_connection_set_fd(rv->tls, fd);
	s2n_connection_set_config(rv->tls, server_config);
	s2n_connection_set_blinding(rv->tls, S2N_SELF_SERVICE_BLINDING);
	s2n_connection_set_ctx(rv->tls, rv);
	rv->low_pri_writes = NULL;
	rv->med_pri_writes = NULL;
	rv->high_pri_writes = NULL;
	rv->highest_stream_seen = 0;
	rv->expect_continuation = false;
	rv->window_size = default_settings.initial_window_size;
	rv->fd = fd;
	rv->timer_fd = timer_fd;
	rv->state = HH_NEGOTIATING_TLS;
	rv->is_write_blocked = false;
	rv->blocked = S2N_NOT_BLOCKED;
	rv->ib_frame.remaining = 0;
	rv->ib_frame.payload = NULL;
	rv->decoder = hpack_decoder(default_settings.header_table_size, -1, hpack_default_alloc);
	rv->root_stream = (struct stream){ .id = 0, .weight = 256, .parent = NULL, .children = NULL, .siblings = NULL };
	memcpy(&rv->settings, &default_settings, sizeof default_settings);
	memset(&rv->ib_frame.header, 0, sizeof rv->ib_frame.header);
	return rv;
cleanup:
	free(rv);
	return NULL;
}

void client_free(struct client *client) {
	// TODO: Wipe the connection, don't free it
	s2n_connection_wipe(client->tls);
	s2n_connection_free(client->tls);
	buf_free_chain(client->low_pri_writes);
	buf_free_chain(client->med_pri_writes);
	buf_free_chain(client->high_pri_writes);
	stream_free_all(client->root_stream.siblings);
	stream_free_all(client->root_stream.children);
	hpack_free(&client->decoder);
	free(client->ib_frame.payload);
	free(client);
}

int close_client(struct client *client) {
	int rv = close(client->fd);
	if (rv < 0)
		log_warn("Call to close(client) failed (%s)", strerror(errno));
	rv = close(client->timer_fd);
	if (rv < 0)
		log_warn("Call to close(client->timer_fd) failed (%s)", strerror(errno));
	client_free(client);
	return rv;
}

// Big state machine.
static int change_state(struct client *client, enum client_state to) {
	if (to == HH_BLINDED) {
		client->state = to;
		return 0;
	}

	switch (client->state) {
		case HH_IDLE:
			switch (to) {
				case HH_TLS_SHUTDOWN:
				case HH_CLOSED:
				case HH_GOAWAY:
					client->state = to;
					break;
				default:
					goto verybad;
			}
			break;
		case HH_WAITING_MAGIC:
			switch (to) {
				case HH_TLS_SHUTDOWN:
				case HH_CLOSED:
				case HH_WAITING_SETTINGS:
					client->state = to;
					break;
				default:
					goto verybad;
			}
			break;
		case HH_WAITING_SETTINGS:
			switch (to) {
				case HH_TLS_SHUTDOWN:
				case HH_CLOSED:
				case HH_GOAWAY:
				case HH_IDLE:
					client->state = to;
					break;
				default:
					goto verybad;
			}
			break;
		case HH_NEGOTIATING_TLS:
			switch (to) {
				case HH_WAITING_MAGIC:
					client->state = to;
					client->ib_frame.remaining = CLIENT_MAGIC_LEN;
					send_settings(client, NULL, false); // Server connection preface
					break;
				case HH_CLOSED:
					client->state = to;
					break;
				default:
					goto verybad;
			}
			break;
		case HH_GOAWAY:
			switch (to) {
				case HH_TLS_SHUTDOWN:
				case HH_GOAWAY:
				case HH_CLOSED:
					break;
				default:
					goto verybad;
			}
			break;
		case HH_TLS_SHUTDOWN:
			switch (to) {
				case HH_TLS_SHUTDOWN: // Treat as no-op for simplicity
					break;
				case HH_CLOSED:
					break;
				default:
					goto verybad;
			}
			break;
		case HH_CLOSED:
		verybad:
		default:
#ifdef NDEBUG
			__builtin_unreachable(); // Helps the optimizer
#else
			log_fatal("You reached the unreachable (client state %d from %d), this is very bad.", to, client->state);
			log_trace();
			exit(-1);
#endif
	}
	return 0;
}

// Initiates a graceful shutdown
// Returns -1 when callers should call close_client
static int send_shutdown(struct client *client) {
	if (s2n_shutdown(client->tls, &client->blocked) < 0) {
		switch(s2n_error_get_type(s2n_errno)) {
			case S2N_ERR_T_BLOCKED:
				change_state(client, HH_TLS_SHUTDOWN);
				return 0;
			default:
				//log_debug("Call to s2n_shutdown failed (%s)", s2n_strerror(s2n_errno, "EN"));
				change_state(client, HH_CLOSED);
				return -1;
		}
	}
	// Graceful shutdown was successful, we can close now
	return -1;
}

// Returns -1 when goaway has been sent
static int wait_goaway(struct client *client) {
	change_state(client, HH_GOAWAY);
	// If there's anything left in the high priority write queue, don't change state yet
	if (client->high_pri_writes != NULL)
		return 0;
	// We can go to TLS shutdown now
	return -1;
}

static int blind_client(struct client *client, uint64_t ns) {
	time_t seconds = ns / 1000000000;
	long nanos = ns % 1000000000;
	struct itimerspec expiry_time = {
		{ 0, 0 }, // Interval time
		{ seconds, nanos }, // Expiry time
	};
	if (ns == 0)
		return -1;
	if (timerfd_settime(client->timer_fd, 0, &expiry_time, NULL) < 0) {
		log_warn("Call to timerfd_settime failed (%s)", strerror(errno));
		return -1;
	}
	change_state(client, HH_BLINDED);
	return 0;
}

int client_on_timer_expired(struct client *client) {
	uint64_t read_buf;
	int rv = read(client->timer_fd, &read_buf, sizeof read_buf);
	if (rv < 0) {
		log_warn("Call to timerfd read failed (%s)", strerror(errno));
		return -1;
	}
	if (client->state == HH_BLINDED)
		return -1;
	else
		log_warn("Timer expired, but client is not blinded");
	return 0;
}

static int do_negotiate(struct client *client) {
	assert(client->state == HH_NEGOTIATING_TLS);
	s2n_errno = S2N_ERR_T_OK;
	errno = 0;
	if (s2n_negotiate(client->tls, &client->blocked) < 0) {
		switch (s2n_error_get_type(s2n_errno)) {
			case S2N_ERR_T_CLOSED:
				return -1;
			case S2N_ERR_T_BLOCKED:
				break;
			case S2N_ERR_T_ALERT:
				log_warn("Call to s2n_negotiate gave alert %d", s2n_connection_get_alert(client->tls));
				break;
			case S2N_ERR_T_PROTO:
				log_debug("Call to s2n_negotiate returned protocol error");
				return blind_client(client, s2n_connection_get_delay(client->tls));
			case S2N_ERR_T_IO:
				// I suppose if ALPN fails, then negotiate will return an error even when successful
				// Skip printing a warning if this happens, but still close the connection.
				if (errno != 0)
					log_warn("Call to s2n_negotiate returned IO error");
				return blind_client(client, s2n_connection_get_delay(client->tls));
			default:
				log_warn("Call to s2n_negotiate failed (%s)", s2n_strerror(s2n_errno, "EN"));
				return blind_client(client, s2n_connection_get_delay(client->tls));
		}
	}
	return 0;
}

static void hpack_decode_event(enum hpack_event_e evt, const char *buf, size_t size, void *priv) {
	(void)size; (void)priv; (void)buf;
	switch (evt) {
		case HPACK_EVT_VALUE:
			//printf(": %s\n", buf);
			break;
		case HPACK_EVT_NAME:
			//printf("%s", buf);
			break;
		default:
			break;
	}
}

static int parse_frame(struct client *client, char *buf, size_t len) {
#define advance(x) ({ bufp += (x); })
#define remaining_len (len - (bufp - buf))
	struct ib_frame *ib = &client->ib_frame;
	char *bufp = buf;

	// Parse client connection preface
	if (client->state == HH_WAITING_MAGIC) {
		size_t read_length = MIN(remaining_len, ib->remaining);
		if (memcmp(CLIENT_MAGIC + CLIENT_MAGIC_LEN - ib->remaining, bufp, read_length) != 0) {
			//log_debug("Invalid client connection preface");
			return -1;
		}
		ib->remaining -= read_length;
		advance(read_length);
		if (ib->remaining == 0) {
			change_state(client, HH_WAITING_SETTINGS);
		} else
			return 0;
		ib->remaining = HH_HEADER_SIZE;
		ib->state = HH_FRAME_HD;
		if (remaining_len == 0)
			return 0;
		// Otherwise we have remaining data to process
	}

	while (1) {
		bool has_full_frame = false; // True when payload is in memory
		switch (ib->state) {
			case HH_FRAME_HD: {
				// Store header in temporary buffer
				size_t read_length = MIN(remaining_len, ib->remaining);
				if (read_length == 0)
					return 0;
				memcpy(ib->temp_buf + HH_HEADER_SIZE - ib->remaining, bufp, read_length);
				advance(read_length);
				ib->remaining -= read_length;
				if (ib->remaining > 0) // Can't do any more processing, wait for rest of header
					return 0;

				// Parse frame header
				uint32_t tmp;
				ib->header.type = ib->temp_buf[3];
				ib->header.flags = ib->temp_buf[4];
				memcpy(&tmp, ib->temp_buf + 5, sizeof(uint32_t));
				ib->header.stream_id = ntohl(tmp & 0x7FFFFFFF);
				memcpy(&tmp, ib->temp_buf, sizeof(uint32_t));
				ib->header.length = ntohl(tmp & 0xFFFFFF00) >> 8;

				// If we were waiting for the initial SETTINGS frame
				if (client->state == HH_WAITING_SETTINGS) {
					// It wasn't a settings frame
					if (ib->header.type != HH_FT_SETTINGS || (ib->header.flags & HH_SETTINGS_ACK) != 0) {
						send_goaway(client, HH_ERR_PROTOCOL);
						goto goaway;
					} else {
						change_state(client, HH_IDLE);
					}
				}

				// Expected a continuation, but our expectation was violated
				if (client->expect_continuation && ib->header.type != HH_FT_CONTINUATION) {
					send_goaway(client, HH_ERR_PROTOCOL);
					goto goaway;
				}

				free(ib->payload);
				ib->payload = NULL;
				if (ib->header.length > 0) {
					ib->payload = malloc(ib->header.length);
					ib->state = HH_FRAME_PAYLOAD;
					ib->remaining = ib->header.length;
				} else {
					ib->remaining = HH_HEADER_SIZE;
					continue;
				}
				__attribute__((fallthrough));
			} case HH_FRAME_PAYLOAD: {
				// Read as much as we can into payload buffer
				size_t read_length = MIN(remaining_len, ib->remaining);
				if (read_length == 0)
					return 0;
				memcpy(ib->payload + (ib->header.length - ib->remaining), bufp, read_length);
				advance(read_length);
				ib->remaining -= read_length;
				// We read the entire payload, now wait for a frame header again
				if (ib->remaining == 0) {
					has_full_frame = true;
					ib->state = HH_FRAME_HD;
					ib->remaining = HH_HEADER_SIZE;
				}
				break;
			}
		}

		if (!has_full_frame)
			continue;

		struct stream *stream = stream_find_id(&client->root_stream, ib->header.stream_id);
		// Check whether the frame is allowed in this state
		if (ib->header.stream_id != 0) {
			int state;
			if (stream != NULL)
				state = stream->state;
			// It's not in the dependency tree, so it must be already closed or not opened
			else if (ib->header.stream_id <= client->highest_stream_seen)
				state = HH_STREAM_CLOSED;
			else
				state = HH_STREAM_IDLE;
			switch (state) {
				case HH_STREAM_IDLE:
					if (ib->header.type != HH_FT_HEADERS
					&& ib->header.type != HH_FT_PRIORITY) {
						send_goaway(client, HH_ERR_PROTOCOL);
						goto goaway;
					}
					break;
				case HH_STREAM_RESERVED_LOCAL:
					if (ib->header.type != HH_FT_RST_STREAM
					&& ib->header.type != HH_FT_PRIORITY
					&& ib->header.type != HH_FT_WINDOW_UPDATE) {
						send_goaway(client, HH_ERR_PROTOCOL);
						goto goaway;
					}
					break;
				case HH_STREAM_RESERVED_REMOTE:
					if (ib->header.type != HH_FT_HEADERS
					&& ib->header.type != HH_FT_RST_STREAM
					&& ib->header.type != HH_FT_PRIORITY) {
						send_goaway(client, HH_ERR_PROTOCOL);
						goto goaway;
					}
					break;
				case HH_STREAM_HCLOSED_REMOTE:
					if (ib->header.type != HH_FT_WINDOW_UPDATE
					&& ib->header.type != HH_FT_PRIORITY
					&& ib->header.type != HH_FT_RST_STREAM) {
						send_rst_stream(client, ib->header.stream_id, HH_ERR_STREAM_CLOSED);
						// TODO: Change stream state to closed
						continue;
					}
					break;
				case HH_STREAM_CLOSED:
					// Technically not standards compliant here. See 5.1@"closed"
					if (ib->header.type != HH_FT_WINDOW_UPDATE
					&& ib->header.type != HH_FT_PRIORITY
					&& ib->header.type != HH_FT_RST_STREAM) {
						send_goaway(client, HH_ERR_PROTOCOL);
						goto goaway;
					}
					break;
				// Otherwise we don't care
				case HH_STREAM_OPEN:
				case HH_STREAM_HCLOSED_LOCAL:
				default:
					break;
			}
		}

		switch (ib->header.type) {
			case HH_FT_SETTINGS:
				// Parse settings frame
				if (ib->header.stream_id != 0 || ib->header.length % 6 != 0) {
					send_goaway(client, ib->header.stream_id != 0 ? HH_ERR_PROTOCOL : HH_ERR_FRAME_SIZE);
					goto goaway;
				} else if ((ib->header.flags & HH_SETTINGS_ACK) != 0) {
					if (ib->header.length != 0) {
						send_goaway(client, HH_ERR_FRAME_SIZE);
						goto goaway;
					}
				} else {
					size_t read = 0;
					while (read < ib->header.length) {
						uint16_t id;
						uint32_t value;
						memcpy(&id, &ib->payload[read], sizeof(uint16_t));
						memcpy(&value, &ib->payload[read + 2], sizeof(uint32_t));
						id = ntohs(id);
						value = ntohl(value);
						read += 6;
						switch (id) {
							case 1:
								client->settings.header_table_size = value;
								break;
							case 2:
								if (value != 0 && value != 1) {
									send_goaway(client, HH_ERR_PROTOCOL);
									goto goaway;
								}
								client->settings.enable_push = value;
								break;
							case 3:
								client->settings.max_concurrent_streams = value;
								break;
							case 4:
								if (value > ((1U << 31) - 1)) {
									send_goaway(client, HH_ERR_FLOW_CONTROL);
									goto goaway;
								}
								client->settings.initial_window_size = value;
								break;
							case 5:
								if (value < (1 << 16) || value > ((1 << 24) - 1)) {
									send_goaway(client, HH_ERR_PROTOCOL);
									goto goaway;
								}
								client->settings.max_frame_size = value;
								break;
							case 6:
								client->settings.max_header_list_size = value;
								break;
							default:
								// Don't error, just ignore
								break;
						}
						//log_debug("Received setting %d, value %#x", id, value);
					}
					// ACKnowledge
					send_settings(client, NULL, true);
				}
				break;
			case HH_FT_WINDOW_UPDATE:
				if (ib->header.length != 4) {
					send_goaway(client, HH_ERR_FRAME_SIZE);
					goto goaway;
				}
				uint32_t increment_size = ntohl(*(uint32_t *)ib->payload) & 0x7FFFFFFF;
				//log_debug("Received WINDOW_UPDATE frame of size %u", increment_size);
				if (ib->header.stream_id == 0) {
					if (increment_size == 0) {
						send_goaway(client, HH_ERR_PROTOCOL);
						goto goaway;
					} else
						// Not realistically going to overflow
						client->window_size += increment_size;
				} else {
					if (stream == NULL || stream->state == HH_STREAM_CLOSED) {
						if (ib->header.stream_id <= client->highest_stream_seen)
							; // It's closed so ignore it 
						else
							assert(0); // Shouldn't happen, we catch IDLE state above
					} else if (increment_size == 0) {
						send_rst_stream(client, ib->header.stream_id, HH_ERR_PROTOCOL);
						// TODO: Change stream state to closed
					} else
						stream->window_size += increment_size;
				}
				break;
			case HH_FT_CONTINUATION:
			case HH_FT_HEADERS:
				if (ib->header.stream_id == 0) {
					send_goaway(client, HH_ERR_PROTOCOL);
					goto goaway;
				}
				char buf[1024];
				struct hpack_decoding dec = {
					.blk = ib->payload,
					.blk_len = ib->header.length,
					.buf = buf,
					.buf_len = sizeof buf,
					.cb = hpack_decode_event,
					.priv = client
				};
				client->expect_continuation = (ib->header.flags & HH_HEADERS_END_HEADERS) == 0;
				if (ib->header.type == HH_FT_HEADERS && ib->header.flags & HH_PADDED) {
					uint8_t pad_len = *(uint8_t *)ib->payload;
					if (pad_len >= ib->header.length) {
						send_goaway(client, HH_ERR_PROTOCOL);
						goto goaway;
					}
					dec.blk_len -= pad_len + 1; // 1 for pad_length
					dec.blk += 1;
				}
				if (ib->header.type == HH_FT_HEADERS && ib->header.flags & HH_PRIORITY) {
					// TODO: Parse stream dependency, exclusive, weight
					if (dec.blk_len < 5) {
						send_goaway(client, HH_ERR_PROTOCOL);
						goto goaway;
					}
					dec.blk_len -= 5;
					dec.blk += 5;
				}
				if (hpack_decode(client->decoder, &dec) < 0) {
					//log_debug("HPACK decoding error");
					send_goaway(client, HH_ERR_COMPRESSION);
					goto goaway;
				}
				break;
			case HH_FT_PING:
				if (ib->header.length != 8) {
					send_goaway(client, HH_ERR_FRAME_SIZE);
					goto goaway;
				} else if (ib->header.stream_id != 0) {
					send_goaway(client, HH_ERR_PROTOCOL);
					goto goaway;
				} else if ((ib->header.flags & HH_PING_ACK) == 0) {
					// We need to ACK the ping
					send_ping(client, (uint8_t *)ib->payload, true);
				}
				break;
			case HH_FT_GOAWAY:
				/*if (ib->header.length >= 8)
					log_debug("Received GOAWAY with code %u", ntohl(*(uint32_t *)&ib->payload[4]));*/
				return -1; // Shutdown gracefully now
				break;
			case HH_FT_RST_STREAM:
				if (ib->header.length != 4) {
					send_goaway(client, HH_ERR_FRAME_SIZE);
					goto goaway;
				} else if (ib->header.stream_id == 0) {
					send_goaway(client, HH_ERR_PROTOCOL);
					goto goaway;
				} else if (stream == NULL || stream->state == HH_STREAM_CLOSED) {
					if (ib->header.stream_id <= client->highest_stream_seen) {
						send_goaway(client, HH_ERR_PROTOCOL);
						goto goaway;
					}
				} else if (stream->state == HH_STREAM_IDLE) {
					send_goaway(client, HH_ERR_PROTOCOL);
					goto goaway;
				} else {
					uint32_t err = ntohl(*(uint32_t *)ib->payload);
					log_debug("RST_STREAM: id %u, err %u", stream->id, err);
				}
				break;
			default:
				break;
		}
	}
	log_trace();
	return 0;
goaway:
	return wait_goaway(client); // do_read() will propogate an exit code up the call stack
}

static int do_read(struct client *client) {
	#define READ_LEN 4096
	char recv_buffer[READ_LEN];
	ssize_t nread;
	int rv = 0;
	do {
		s2n_errno = S2N_ERR_T_OK;
		if ((nread = s2n_recv(client->tls, recv_buffer, READ_LEN, &client->blocked)) < 0) {
			switch (s2n_error_get_type(s2n_errno)) {
				case S2N_ERR_T_CLOSED:
					rv = -1;
					goto loop_end;
				case S2N_ERR_T_BLOCKED:
					break;
				case S2N_ERR_T_IO:
					rv = blind_client(client, s2n_connection_get_delay(client->tls));
					goto loop_end;
				default:
					log_warn("s2n_recv: %s\n", s2n_strerror(s2n_errno, "EN"));
					rv = blind_client(client, s2n_connection_get_delay(client->tls));
					goto loop_end;
			}
		} else if (nread == 0) {
			// Client disconnected, signal shutdown
			rv = -1;
			goto loop_end;
		} else {
			if (parse_frame(client, recv_buffer, nread) < 0) {
				rv = -1;
				goto loop_end;
			}
		}
	} while (client->blocked == S2N_NOT_BLOCKED);
loop_end:
	return rv;
}

static int signal_epollout(struct client *client, bool on) {
	struct epoll_event ev;
	ev.data.ptr = client;
	ev.events = CLIENT_EPOLL_EVENTS;
	if (on)	ev.events |= EPOLLOUT;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev) < 0)
		return -1;
	return 0;
}

static int do_write(struct client *client) {
	struct buf_chain **pending;
	do {
		// Write the highest priority data first
		pending = &client->low_pri_writes;
		if (client->high_pri_writes != NULL)
			pending = &client->high_pri_writes;
		else if (client->med_pri_writes != NULL)
			pending = &client->med_pri_writes;

		// Ensure we still have data to write
		if (*pending == NULL)
			return 0;

		// If we're in the GOAWAY state, stop writing if not high priority
		if (pending != &client->high_pri_writes && client->state == HH_GOAWAY) {
			return 0;
		}

		ssize_t nwritten;
		s2n_errno = S2N_ERR_T_OK;
		ssize_t write_len = (*pending)->len - (*pending)->offset;
		char *buf_start = (*pending)->data + (*pending)->offset;
		nwritten = s2n_send(client->tls, buf_start, write_len, &client->blocked);
		if (nwritten < 0) {
			switch (s2n_error_get_type(s2n_errno)) {
				case S2N_ERR_T_CLOSED:
					return -1;
				case S2N_ERR_T_BLOCKED:
					break;
				case S2N_ERR_T_IO:
					return blind_client(client, s2n_connection_get_delay(client->tls));
				default:
					log_warn("s2n_recv: %s\n", s2n_strerror(s2n_errno, "EN"));
					return blind_client(client, s2n_connection_get_delay(client->tls));
			}
		} else {
			// We stil have data to write
			if (nwritten < write_len) {
				(*pending)->offset += nwritten;
			} else {
				// Else we have exhausted all the data in this buffer
				struct buf_chain *buf = buf_pop_chain(pending);
				free(buf);
			}
		}
	} while (client->blocked == S2N_NOT_BLOCKED);

	// We still have data remaining, signal EPOLLOUT
	if (*pending != NULL && !client->is_write_blocked) {
		client->is_write_blocked = true;
		if (signal_epollout(client, true) < 0)
			return -1;
	} else if (*pending == NULL && client->is_write_blocked) {
		// All data is now written, clear EPOLLOUT
		client->is_write_blocked = false;
		if (signal_epollout(client, false) < 0)
			return -1;
	}

	return 0;
}

int client_queue_write(struct client *client, enum write_pri pri, char *data, size_t len) {
	struct buf_chain *last, **target;
	switch (pri) {
		case HH_PRI_HIGH:
			target = &client->high_pri_writes;
			break;
		case HH_PRI_MED:
			target = &client->med_pri_writes;
			break;
		case HH_PRI_LOW:
			target = &client->low_pri_writes;
			break;
		default:
			log_trace();
			abort();
	}
	if (*target == NULL) {
		*target = buf_alloc();
		last = *target;
	} else
		// TODO: Make O(1)
		for (last = *target; last->next != NULL; last = last->next)
			;

	if (last->len < BUF_SIZE) {
		size_t write_size = MIN(BUF_SIZE - last->len, len);
		memcpy(last->data + last->len, data, write_size);
		last->len += write_size;
		data += write_size;
		len -= write_size;
	}

	// Now buffer is either filled or we have written all the data
	while (len > 0) {
		struct buf_chain *buf = buf_alloc();
		size_t write_size = MIN(BUF_SIZE, len);
		memcpy(buf->data, data, write_size);
		data += write_size;
		len -= write_size;
		buf->len = write_size;
		last->next = buf;
		last = buf;
	}

	// If we can write it now, do it
	if (!client->is_write_blocked)
		return do_write(client);
	return 0;
}

int client_on_write_ready(struct client *client) {
	switch (client->state) {
		case HH_NEGOTIATING_TLS:
			if (client->blocked == S2N_BLOCKED_ON_READ)
				break;
			if (do_negotiate(client) < 0)
				goto error;
			if (client->blocked == S2N_NOT_BLOCKED)
				change_state(client, HH_WAITING_MAGIC);
			break;
		case HH_WAITING_MAGIC:
			log_trace(); // This shouldn't happen
			break;
		case HH_WAITING_SETTINGS: // Keep sending SETTINGS frame
		case HH_IDLE:
			if (do_write(client) < 0)
				goto graceful_exit;
			break;
		case HH_GOAWAY:
			if (do_write(client) < 0)
				goto graceful_exit;
			if (wait_goaway(client) < 0)
				goto graceful_exit;
			break;
		case HH_TLS_SHUTDOWN:
			if (send_shutdown(client) < 0)
				goto error;
			break;
		default:
#ifdef NDEBUG
			__builtin_unreachable();
#else
			log_fatal("Unknown client state %d", client->state);
			exit(-1);
#endif
	}
	return 0;

graceful_exit:
	if (send_shutdown(client) < 0)
		goto error;
	return 0;
error:
	close_client(client);
	return -1;
}

int client_on_data_received(struct client *client) {
	switch (client->state) {
		case HH_NEGOTIATING_TLS:
			if (client->blocked == S2N_BLOCKED_ON_WRITE) {
				fprintf(stderr, "Unexpected data on client socket\n");
				goto error;
			}
			if (do_negotiate(client) < 0)
				goto error;
			if (client->blocked == S2N_NOT_BLOCKED)
				// Might we need to check that there is no more data available?
				change_state(client, HH_WAITING_MAGIC);
			break;
		case HH_WAITING_MAGIC:
		case HH_WAITING_SETTINGS:
		case HH_IDLE:
			if (do_read(client) < 0)
				goto graceful_exit;
			break;
		case HH_GOAWAY:
			/*if (wait_goaway(client) < 0)
				goto graceful_exit;*/
			break;
		case HH_TLS_SHUTDOWN:
			if (send_shutdown(client) < 0)
				goto error;
			break;
		default:
#ifdef NDEBUG
			__builtin_unreachable();
#else
			log_fatal("Unknown client state %d", client->state);
			exit(-1);
#endif
	}
	return 0;

graceful_exit:
	if (send_shutdown(client) < 0)
		goto error;
	return 0;
error:
	close_client(client);
	return -1;
}
