#ifndef _PNA_HASHMAP_H_
#define _PNA_HASHMAP_H_

#include <stdint.h>

/**
 * policies:
 * - key and value are defined by user of pna_hashmap
 * - key must be first thing in a pair (match is confirmed by comparing
 *   first key_size bytes of a pair)
 * - key_size is the number of bytes used for a key
 * - pair_size (= key_size + value_size) is used for memory allocation of
 *   hash table
 *
 * bugs:
 * - key and value should be aligned sizes, i.e.:
 *   sizeof(key) + sizeof(value) == sizeof(pair)
 */

/* based on Jon Turner's Cpp HashMap implementation */
#define BKT_SIZE   8 /**< size of one bucket */
typedef uint32_t bkt_t[BKT_SIZE];
struct pna_hashmap {
    uint32_t n_pairs;    /**< number of entries */
    uint32_t key_size;   /**< size of a pair key (for comparisons) */
    uint32_t value_size; /**< size of a pair value */
    uint32_t n_buckets;  /**< number of buckets */
    int bkt_mask;        /**< bucket mask */
    int kvx_mask;        /**< key-value index mask */
    int fp_mask;         /**< fingerprint mask */
    uint32_t next_idx;   /**< next pair index to use */
    bkt_t *buckets;      /**< buckets */
    char *pairs;         /**< key-value store */
#define MAP_PAIR(m, i) ((m)->pairs[((m)->key_size+(m)->value_size)*(i)])
};

/* size of all buckets in bytes */
#define BKTS_BYTES(map) (2*(map)->n_buckets*sizeof(*(map)->buckets))
/* size of all pairs in bytes */
#define PAIRS_BYTES(map) ((map)->n_pairs*((map)->key_size+(map)->value_size))

/* allocatable hashmaps */
#define PNA_NHASHMAPS 8

/* prototypes */
struct pna_hashmap *hashmap_create(uint32_t n_pairs, uint32_t key_size, uint32_t value_size);
void hashmap_destroy(struct pna_hashmap *map);
void hashmap_reset(struct pna_hashmap *map);
void *hashmap_get(struct pna_hashmap *map, void *key);
void *hashmap_put(struct pna_hashmap *map, void *key, void *value);

#endif /* _PNA_HASHMAP_H_ */
