#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pna_hashmap.h"

void MurmurHash3_x64_128(const void *, const int, const uint32_t, void *);

/* local prototypes */
static void hashmap_hashit(struct pna_hashmap *map, void *key, int func, uint32_t *b, uint32_t *fp);
#define pna_error printf

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

    if (NULL == (map->buckets = (bkt_t *)malloc(BKTS_BYTES(map)))) {
        pna_error("Error could not allocate memory for buckets");
        return NULL;
    }
    if (NULL == (map->pairs = (char *)malloc(PAIRS_BYTES(map)))) {
        pna_error("Error could not allocate memory for pairs");
        return NULL;
    }
    map->next_idx = 0;

    /* XXX remove debug */
    //printf("buckets for %d * %d * %d [* %d, %d]\n", 2, map->n_buckets,
    //        BKT_SIZE, sizeof(*map->buckets), sizeof(**map->buckets));
    //printf("buckets@0x%llx (%d)\n", map->buckets, BKTS_BYTES(map));
    //printf("pairs@0x%llx (%d)\n", map->pairs, PAIRS_BYTES(map));
    //printf("n_pairs: %d\n", map->n_pairs);
    //printf("n_buckets: %d (0x%08x)\n", map->n_buckets, map->bkt_mask);

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
    free(map->buckets);
    free(map->pairs);
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
static void hashmap_hashit(struct pna_hashmap *map, void *key, int func, uint32_t *b, uint32_t *fp)
{
    uint64_t out[2];

    /* main hashing routine */
#define C0 0xa96347c5
#define C1 0xe65ac2d3
    MurmurHash3_x64_128(key, map->key_size, func ? C0 : C1, out);

    //printf("hash: 0x%16llx:%16llx\n", out[0], out[1]);

    *b = out[0] & map->bkt_mask;
    *fp = out[1] & map->fp_mask;
}

/**
 * Get a pointer to a key-value pair, based on the given key.
 * @return pointer to the pair index, NULL if failure
 */
void *hashmap_get(struct pna_hashmap *map, void *key)
{
    int i;
    uint32_t bkt, kvx, fp;

    /* scan bucket of the first section */
    hashmap_hashit(map, key, 0, &bkt, &fp);
    for (i = 0; i < BKT_SIZE; i++) {
        /* XXX remove debug */
        //printf("bkt = %d ; i = %d\n", bkt, i);
        //printf("buckets@0x%llx\n", map->buckets);
        //printf("buckets[%d]@0x%llx\n", bkt, &map->buckets[bkt]);
        //printf("buckets[%d][%d]@0x%llx\n", bkt, i, &(map->buckets[bkt][i]));
        if ((map->buckets[bkt][i] & map->fp_mask) == fp) {
            kvx = map->buckets[bkt][i] & map->kvx_mask;
            /* check for positive match */
            if (0 == memcmp(&MAP_PAIR(map, kvx), key, map->key_size))
                return &MAP_PAIR(map, kvx);
        }
    }
    /* scan bucket of the second section */
    hashmap_hashit(map, key, 1, &bkt, &fp);
    bkt += map->n_buckets;
    for (i = 0; i < BKT_SIZE; i++) {
        if ((map->buckets[bkt][i] & map->fp_mask) == fp) {
            kvx = map->buckets[bkt][i] & map->kvx_mask;
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
        return 0;

    /* count used buckets in left half */
    hashmap_hashit(map, key, 0, &b0, &fp0);
    n0 = 0;
    for (i = 0; i < BKT_SIZE; i++) {
        if (map->buckets[b0][i] == 0) {
            n0++;
            i0 = i;
        }
    }
    /* count used buckets in right half */
    hashmap_hashit(map, key, 1, &b1, &fp1);
    b1 += map->n_buckets;
    n1 = 0;
    for (i = 0; i < BKT_SIZE; i++) {
        if (map->buckets[b1][i] == 0) {
            n1++;
            i1 = i;
        }
    }

    /* if both halves are full, quit */
    if (n0 + n1 == 0)
        return 0;

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

#if 0
struct my_pair {
    uint64_t key;
    struct {
        int a;
        int b;
        short c;
    } value;
};

int main(int argc, char **argv)
{
    struct pna_hashmap *map;
    struct my_pair *pair;

    /* local pair */
    struct my_pair p0, p1, p2;
    p0.key = 0x00;
    p0.value.a = 4*1;
    p0.value.b = 4*11;
    p0.value.c = 4*111;

    p1.key = 0x01;
    p1.value.a = 5*1;
    p1.value.b = 5*11;
    p1.value.c = 5*111;

    map = hashmap_create(16, sizeof(p0.key), sizeof(p0.value));
    printf("key size: %d\n", sizeof(p0.key));


    pair = hashmap_put(map, &(p0.key), &(p0.value));
    printf("Put p0 @ 0x%llx\n", pair);

    pair = hashmap_put(map, &(p1.key), &(p1.value));
    printf("Put p1 @ 0x%llx\n", pair);

    printf("p0@0x%08x: {%llx, %d, %d, %d}\n", &p0, p0.key,
            p0.value.a, p0.value.b, p0.value.c);

    printf("pair(p1)@0x%08x: {%llx, %d, %d, %d}\n", pair, pair->key,
            pair->value.a, pair->value.b, pair->value.c);

    pair = hashmap_get(map, &(p0.key));
    if (pair) {
        /* update */
        printf("Found pair @ 0x%llx\n", pair);
    }
    else {
        pair = hashmap_put(map, &(p0.key), &(p0.value));
        printf("Put pair @ 0x%llx\n", pair);
    }
    printf("pair(p0)@0x%08x: {%llx, %d, %d, %d}\n", pair, pair->key,
            pair->value.a, pair->value.b, pair->value.c);

    pair = hashmap_get(map, &(p1.key));
    if (pair) {
        /* update */
        printf("Found pair @ 0x%llx\n", pair);
    }
    else {
        pair = hashmap_put(map, &(p1.key), &(p1.value));
        printf("Put pair @ 0x%llx\n", pair);
    }
    printf("pair(p1)@0x%08x: {%llx, %d, %d, %d}\n", pair, pair->key,
            pair->value.a, pair->value.b, pair->value.c);
}
#endif
