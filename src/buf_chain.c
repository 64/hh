#include <stdlib.h>
#include <assert.h>

#include "client.h"
#include "buf_chain.h"
#include "log.h"

struct buf_chain *buf_alloc(void) {
	struct buf_chain *rv = malloc(sizeof *rv);
	rv->len = 0;
	rv->next = NULL;
	rv->offset = 0;
	return rv;
}

void buf_free_chain(struct buf_chain *chain) {
	struct buf_chain *head, *temp;
	for (head = chain; head != NULL; head = temp) {
		temp = head->next;
		free(head);
	}
}

struct buf_chain *buf_pop_chain(struct buf_chain **chain) {
	if (chain == NULL)
		return NULL;
	struct buf_chain *rv = *chain;
	*chain = (*chain)->next;
	return rv;
}
