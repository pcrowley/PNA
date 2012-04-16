
/* Based on Jon Turner's 2011 HashMap.cpp implementation */

#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/string.h>

#include "pna_hashmap.h"

// XXX should move to pna.h
// and be used everywhere...
#define pna_error pr_err

/* local prototypes */
static void hashmap_hashit(struct pna_hashmap *map, void *key, uint32_t *b0,
                           uint32_t *fp0, uint32_t *b1, uint32_t *fp1);

/* murmur3 prototype */
void MurmurHash3_x64_128(const void *key, const int len, const uint32_t seed, void *out);

/* variable def */
static struct pna_hashmap hashmaps[PNA_NHASHMAPS];

/**
 * Create a hashmap for storing data on the fly.
 *
 * @param n_pairs number of entries in the hashmap
 * @param key_size size of the key of a pair
 * @param value_size size of the value of a pair
 * @return pointer to the hashmap wrapper
 */
struct pna_hashmap *hashmap_create(uint32_t n_pairs, uint32_t key_size, uint32_t value_size)
{
    int i;
    struct pna_hashmap *map;

    /* find a free hashmap */
    for (i = 0; i < PNA_NHASHMAPS; i++) {
        map = &hashmaps[i];
        if (map->n_pairs == 0)
            break;
    }
    if (i == PNA_NHASHMAPS) {
        pna_error("Error all hashmaps are in use");
        return NULL;
    }

    map->n_pairs = n_pairs;
    map->key_size = key_size;
    map->value_size = value_size;

    /* need at least 4 buckets */
    map->n_buckets = 4;
    while (8*map->n_buckets <= map->n_pairs) {
        map->n_buckets <<= 1;
    }

    map->bkt_mask = map->n_buckets - 1;
    map->kvx_mask = (8*map->n_buckets) - 1;
    map->fp_mask = ~(map->kvx_mask);

    if (NULL == (map->buckets = vmalloc(BKTS_BYTES(map)))) {
        pna_error("Error could not allocate memory for buckets");
        return NULL;
    }
    if (NULL == (map->pairs = vmalloc_user(PAIRS_BYTES(map)))) {
        pna_error("Error could not allocate memory for pairs");
        return NULL;
    }
    map->next_idx = 0;

    hashmap_reset(map);

    return map;
}

/**
 * Destroy a hashmap from the system
 * @param *map hashmap to destroy
 */
void hashmap_destroy(struct pna_hashmap *map)
{
    hashmap_reset(map);
    vfree(map->buckets);
    vfree(map->pairs);
    map->fp_mask = 0;
    map->kvx_mask = 0;
    map->bkt_mask = 0;
    map->n_buckets = 0;
    map->key_size = 0;
    map->value_size = 0;
    map->n_pairs = 0;
}

/**
 * Reset all the pairs, buckets, and meta-data for a hashmap
 * @param *map hashmap to reset
 */
void hashmap_reset(struct pna_hashmap *map)
{
    /* clear all buckets */
    memset(map->buckets, 0, BKTS_BYTES(map));
    /* clear all pairs */
    memset(map->pairs, 0, PAIRS_BYTES(map));
    /* reset next_idx */
    map->next_idx = 0;
}

/**
 * Hashit builds a hash of the key and returns the bucket to use and a
 * fingerprint value.
 * @param key 64-bit key to hash
 * @param func hash function to use
 * @param *b pointer to location of bucket return value
 * @param *fp pointer to location of fingerprint return value
 */
static void hashmap_hashit(struct pna_hashmap *map, void *key, uint32_t *b0, uint32_t *fp0, uint32_t *b1, uint32_t *fp1)
{
    uint64_t out[2];

    /* main hashing routine */
    MurmurHash3_x64_128(key, map->key_size, 0xa96347c5, out);

    /* XXX: Not sure if this is a good idea or bad idea:
     * we get back 128 bits, but only need 4 <32-bit pieces of data
     * so split of the return hash in uniqe ways to produce the data */
    *b0 = (out[1] >> 32) & map->bkt_mask;
    *fp0 = (out[0]) & map->fp_mask;
    *b1 = ((out[0] >> 32) & map->bkt_mask) + map->n_buckets;
    *fp1 = (out[1]) & map->fp_mask;
}

/**
 * Get a pointer to a key-value pair, based on the given key.
 * @return pointer to the pair index, NULL if failure
 */
void *hashmap_get(struct pna_hashmap *map, void *key)
{
    int i;
    uint32_t kvx;
    uint32_t b0, fp0, b1, fp1;

    hashmap_hashit(map, key, &b0, &fp0, &b1, &fp1);
    for (i = 0; i < BKT_SIZE; i++) {
        /* scan bucket of the first section */
        if ((map->buckets[b0][i] & map->fp_mask) == fp0) {
            kvx = map->buckets[b0][i] & map->kvx_mask;
            /* check for positive match */
            if (0 == memcmp(&MAP_PAIR(map, kvx), key, map->key_size))
                return &MAP_PAIR(map, kvx);
        }
        /* scan bucket of the second section */
        if ((map->buckets[b1][i] & map->fp_mask) == fp1) {
            kvx = map->buckets[b1][i] & map->kvx_mask;
            /* check for positive match */
            if (0 == memcmp(&MAP_PAIR(map, kvx), key, map->key_size))
                return &MAP_PAIR(map, kvx);
        }
    }

    /* nothing found in the 2*BKT_SIZE slots? give up. */
    return NULL;
}

/**
 * Put
 * @return 1 if entry successfully inserted, 0 if failure
 */
void *hashmap_put(struct pna_hashmap *map, void *key, void *value)
{
    int i, n0, i0, n1, i1;
    uint32_t b0, fp0, b1, fp1;
    int idx;
    char *pair;

    /* check if table is full */
    if (map->next_idx >= map->n_pairs)
        return NULL;

    hashmap_hashit(map, key, &b0, &fp0, &b1, &fp1);
    i0 = n0 = i1 = n1 = 0;
    for (i = 0; i < BKT_SIZE; i++) {
        /* count used buckets in left half */
        if (map->buckets[b0][i] == 0) {
            n0++;
            i0 = i;
        }
        /* count used buckets in right half */
        if (map->buckets[b1][i] == 0) {
            n1++;
            i1 = i;
        }
    }

    /* if both halves are full, quit */
    if (n0 + n1 == 0)
        return NULL;

    /* store the value in least-loaded bucket */
    idx = map->next_idx;
    map->next_idx += 1;
    /* store the key and values for this pair */
    pair = &MAP_PAIR(map, idx);
    memcpy(pair, key, map->key_size);
    memcpy(pair+map->key_size, value, map->value_size);
    /* update the bucket entry */
    if (n0 >= n1)
        map->buckets[b0][i0] = fp0 | (idx & map->kvx_mask);
    else
        map->buckets[b1][i1] = fp1 | (idx & map->kvx_mask);

    return pair;
}

