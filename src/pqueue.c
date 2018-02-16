#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "pqueue.h"
#include "frame.h"
#include "log.h"

void pqueue_init(struct pqueue *pqueue) {
	pqueue->high_pri = NULL;
	pqueue->med_pri = NULL;
	pqueue->low_pri = NULL;
	pqueue->write_head = HH_PRI_NONE;
}

void pqueue_free(struct pqueue *pqueue) {
	free(pqueue->high_pri);
	free(pqueue->med_pri);
	free(pqueue->low_pri);
}

struct pqueue_node *pqueue_node_alloc(size_t len) {
	size_t alloc_len = len + sizeof(struct pqueue_node);
	struct pqueue_node *rv = malloc(alloc_len);
	rv->nwritten = 0;
	rv->next = NULL;
	return rv;
}

void pqueue_node_free(struct pqueue_node *frame) {
	free(frame);
}

static size_t frame_size(struct pqueue_node *frame) {
	uint32_t tmp = 0;
	memcpy(&tmp, frame->data, 3); // Length is first 3 bytes of 'data'
	tmp = ntohl(tmp << 8) & 0x00FFFFFF;
	return (size_t)tmp + HH_HEADER_SIZE;
}

#if 0
static void debug_log_frame(struct pqueue_node *frame) {
	uint8_t  type = frame->data[3];
	uint32_t s_id = 0;
	memcpy(&s_id, frame->data + 5, 4);
	s_id = ntohl(s_id);
	log_debug("Type %u, ID %u", type, s_id);
}
#endif

int pqueue_submit_frame(struct pqueue *pqueue, struct pqueue_node *frame, enum pqueue_pri priority) {
	struct pqueue_node **head = NULL, *tmp;
	assert(priority != HH_PRI_NONE);
	assert(frame != NULL && frame->next == NULL);
	switch (priority) {
		case HH_PRI_HIGH:
			head = &pqueue->high_pri;
			break;
		case HH_PRI_MED:
			head = &pqueue->med_pri;
			break;
		case HH_PRI_LOW:
			head = &pqueue->low_pri;
			break;
		default:
			// TODO: Cleanup
			log_trace();
			__builtin_unreachable();
			break;
	}

	if (*head == NULL)
		*head = frame;
	else {
		tmp = *head;
		while (tmp->next != NULL)
			tmp = tmp->next;
		tmp->next = frame; // Append
	}
	return 0;
}

int pqueue_pop_next(struct pqueue *pqueue, struct pqueue_node **out_frame, char **out_data, size_t *out_len) {
	struct pqueue_node **head = NULL;
	switch (pqueue->write_head) {
		case HH_PRI_HIGH:
			head = &pqueue->high_pri;
			break;
		case HH_PRI_MED:
			head = &pqueue->med_pri;
			break;
		case HH_PRI_LOW:
			head = &pqueue->low_pri;
			break;
		case HH_PRI_NONE:
			// Take whichever queue has the highest priority
			if (pqueue->high_pri != NULL)
				head = &pqueue->high_pri;
			else if (pqueue->med_pri != NULL)
				head = &pqueue->med_pri;
			else if (pqueue->low_pri != NULL)
				head = &pqueue->low_pri;
			else {
				// Nothing to write
				*out_frame = NULL;
				return -1;
			}
			break;
	}

	// Debugging
	if (pqueue->write_head == HH_PRI_NONE)
		assert((*head)->nwritten == 0);

	size_t total_frame_len = frame_size(*head);
	assert(total_frame_len > (*head)->nwritten);
	*out_data = (*head)->data + (*head)->nwritten;
	*out_len = total_frame_len - (*head)->nwritten;
	*out_frame = (*head);
	return 0;
}

int pqueue_report_write(struct pqueue *pqueue, struct pqueue_node *frame, size_t len_written) {
	struct pqueue_node **origin;
	enum pqueue_pri pri;
	if (frame == pqueue->high_pri) {
		origin = &pqueue->high_pri;
		pri = HH_PRI_HIGH;
	} else if (frame == pqueue->med_pri) {
		origin = &pqueue->med_pri;
		pri = HH_PRI_MED;
	} else if (frame == pqueue->low_pri) {
		origin = &pqueue->low_pri;
		pri = HH_PRI_LOW;
	} else {
		log_trace();
		abort();
	}

	//debug_log_frame(frame);

	frame->nwritten += len_written;
	if (frame->nwritten >= frame_size(frame)) {
		// Frame fully written, clean up
		struct pqueue_node *tmp = frame->next;
		pqueue_node_free(frame);
		*origin = tmp;
		pqueue->write_head = HH_PRI_NONE; // Free up the other queues for writing
	} else
		pqueue->write_head = pri;
	return 0;

}

bool pqueue_is_data_pending(struct pqueue *pqueue) {
	return pqueue->high_pri || pqueue->med_pri || pqueue->low_pri;
}
