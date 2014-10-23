/*
   Code to peform longest prefix match on an IP and return the domain to
   which it belongs.  All inputs must be in network byte order

 */

#include "pna.h"

/* locally used structs */
struct pna_dtrie_entry {
	int isprefix;
	unsigned short domain_id;
	struct pna_dtrie_entry *children[2];
};

struct pna_dtrie_entry *pna_dtrie_head;

struct pna_dtrie_entry *pna_dtrie_entry_alloc()
{
	struct pna_dtrie_entry *entry =
		(struct pna_dtrie_entry*)malloc(sizeof(struct pna_dtrie_entry));

	if (!entry)
		return NULL;
	entry->domain_id = MAX_DOMAIN;
	entry->isprefix = 0;
	memset(entry->children, 0, 2 * sizeof(struct pna_domain_entry *));
	return entry;
}



unsigned int pna_dtrie_lookup(unsigned int ip)
{
	unsigned int cur_bit, cur_bit_pos;
	struct pna_dtrie_entry *next_entry;
	struct pna_dtrie_entry *entry = pna_dtrie_head;
	unsigned int curdomain = MAX_DOMAIN;

	//assume network byte order
	cur_bit_pos = 0;
	cur_bit = (ip >> (31 - cur_bit_pos)) & 0x1;
	next_entry = entry->children[cur_bit];
	while (next_entry) {
		entry = next_entry;
		if (entry->isprefix)
			curdomain = entry->domain_id;
		cur_bit_pos++;
		cur_bit = (ip >> (31 - cur_bit_pos)) & 1;
		next_entry = entry->children[cur_bit];
	}
	return curdomain;
}

int pna_dtrie_add(unsigned int prefix, unsigned int max_bit_pos,
		  unsigned int domain_id)
{
	unsigned int cur_bit_pos;
	unsigned int cur_bit;
	struct pna_dtrie_entry *next;
	struct pna_dtrie_entry *cur = pna_dtrie_head;

	printf("pna_dtrie_add %X %i %i\n", prefix, max_bit_pos, domain_id);

	cur_bit_pos = 0;
	while (cur_bit_pos < max_bit_pos) {
		cur_bit = (prefix >> (31 - cur_bit_pos)) & 0x1;
		next = cur->children[cur_bit];
		if (!next) {
			cur->children[cur_bit] = next = pna_dtrie_entry_alloc();
			if (!next) {
				printf("Failed to alloc dtrie entry\n");
				return -1;
			}
		}
		cur_bit_pos++;
		cur = next;
	}
	cur->isprefix = 1;
	cur->domain_id = domain_id;
	return 0;
}


int pna_dtrie_rm_node(struct pna_dtrie_entry *entry)
{
	if (!entry)
		return 0;
	pna_dtrie_rm_node(entry->children[0]);
	pna_dtrie_rm_node(entry->children[1]);
	free(entry);
	return 0;
}

int pna_dtrie_deinit()
{
	pna_dtrie_rm_node(pna_dtrie_head);
	printf("pna dtrie freed\n");
	return 0;
}

int pna_dtrie_init()
{
	pna_dtrie_head = pna_dtrie_entry_alloc();
	if (!pna_dtrie_head) {
		printf("failed to init dtrie head\n");
		return -1;
	}

	return 0;
}
