#pragma once

#include <stddef.h>
#include <stdint.h>

struct pqueue_node {
	struct pqueue_node *next;
	size_t nwritten;
	char data[];
};

enum pqueue_pri {
	HH_PRI_NONE,
	HH_PRI_HIGH,
	HH_PRI_MED,
	HH_PRI_LOW,
};

struct pqueue {
	struct pqueue_node *high_pri;
	struct pqueue_node *med_pri;
	struct pqueue_node *low_pri;
	enum pqueue_pri write_head;
};

void pqueue_init(struct pqueue *pqueue);
void pqueue_free(struct pqueue *pqueue);
struct pqueue_node *pqueue_node_alloc(size_t len);
void pqueue_node_free(struct pqueue_node *frame);
int pqueue_submit_frame(struct pqueue *pqueue, struct pqueue_node *frame, enum pqueue_pri priority);
int pqueue_pop_next(struct pqueue *pqueue, struct pqueue_node **out_frame, char **out_data, size_t *out_len);
int pqueue_report_write(struct pqueue *pqueue, struct pqueue_node *frame, size_t len_written);
bool pqueue_is_data_pending(struct pqueue *pqueue);
