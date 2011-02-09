struct lip_entry *do_lip_entry(struct flowtab_info *info, uint local_ip,
        uint direction)
{
    struct lip_entry *lip_entry;
    unsigned int i;
    unsigned int hash, hash_0, hash_1;
    
    hash_0 = hash_32(local_ip, PNA_LIP_BITS);
    hash_1 = hash_pna(local_ip, PNA_LIP_BITS);

    /* loop through table until we find right entry */
    for ( i = 0; i < PNA_TABLE_TRIES; i++ ) {
        /* use linear probing for next entry */
        //hash = (hash_0 + i) & (PNA_LIP_ENTRIES-1);
        /* double hashing for entry */
        hash = (hash_0 + i*hash_1) & (PNA_LIP_ENTRIES-1);

        /* start testing the waters */
        lip_entry = &info->lips[hash];

        /* check if IP is a match */
        if (local_ip == lip_entry->local_ip) {
            return lip_entry;
        }

        /* check if IP is clear */
        if (0 == lip_entry->local_ip) {
            /* set up entry and return it */
            lip_entry->local_ip = local_ip;
            info->nlips++;
            return lip_entry;
        }
    }
   
    info->nlips_missed++;
    return (struct lip_entry *)NULL;
}

/* Find and set/update the level 2 table entry */
struct rip_entry *do_rip_entry(struct flowtab_info *info,
        struct lip_entry *lip_entry, uint remote_ip, uint direction)
{
    struct rip_entry *rip_entry;
    pna_bitmap rip_bits;
    unsigned int i;
    unsigned int hash, hash_0, hash_1;
    
    hash = lip_entry->local_ip ^ remote_ip;

    hash_0 = hash_32(hash, PNA_RIP_BITS);
    hash_1 = hash_pna(hash, PNA_RIP_BITS);

    /* loop through table until we find right entry */
    for ( i = 0; i < PNA_TABLE_TRIES; i++ ) {
        /* double hashing for entry */
        hash = (hash_0 + i*hash_1) & (PNA_RIP_ENTRIES-1);

        /* start testing the waters */
        rip_entry = &info->rips[hash];
        rip_bits = lip_entry->dsts[hash/BITMAP_BITS];

        /* check for match */
        if ( remote_ip == rip_entry->remote_ip
            && 0 != (rip_bits & (1 << hash % BITMAP_BITS))) {
            if ( 0 == (rip_entry->info_bits & (1 << direction)) ) {
                /* we haven't seen this direction yet, add it */
                lip_entry->ndsts[direction]++;
                /* indicate that we've seen this direction */
                rip_entry->info_bits |= (1 << direction);
            }
            return rip_entry;
        }

        /* check for free spot */
        if ( 0 == rip_entry->remote_ip ) {
            /* set index of src IP */
            lip_entry->dsts[hash/BITMAP_BITS] |= (1 << (hash % BITMAP_BITS));
            /* set all fields if a match */
            rip_entry->remote_ip = remote_ip;
            /* update the number of connections */
            lip_entry->ndsts[direction]++;
            /* indicate that we've seen this direction */
            rip_entry->info_bits |= (1 << direction);
            /* first time this remote IP was seen it was travelling ... */
            rip_entry->info_bits |= (1 << (direction + PNA_DIRECTIONS));

            info->nrips++;
            return rip_entry;
        }
    }

    info->nrips_missed++;
    return (struct rip_entry *)NULL;
}
