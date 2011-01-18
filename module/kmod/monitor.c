
/*
 * procfs monitor function
 */

/* count the number of 1 bits in an array of bits */
unsigned int bitcount(void *array, unsigned int bytesize)
{
    unsigned int count, pos, chunk;

    count = 0;
    for ( pos = 0; pos < bytesize; pos += sizeof(unsigned int) )
    {
        chunk = *(unsigned int *)(array+pos);
        /*
        count += __builtin_popcount(chunk);
        */
        while (chunk)  {
            count++ ;
            chunk &= (chunk - 1) ;
        }
    }

    return count;
}

atomic_t rec_count[NTABS];

int monitor_read(char *buffer, char **buffer_location, off_t offset, 
                 int buffer_length, int *eof, void *data)
{
	int lip_count, rip_count, prt_count;
	int lip_excess, rip_excess, prt_excess;
    int buf_idx;
    watch_data_t *monitor;
    watch_port_t *port;
    nf_bitmap bitmap;
    struct nf_lip_entry *lip_entry;
    struct nf_rip_entry *rip_entry;
    struct nf_prt_entry *prt_entry;
    smp_info_t *smp = (smp_info_t *)data;
	int tab_id = smp->id;
    buf_idx = 0;

    if (debug) printk("new call: %d (%d)\n", buffer_length, tab_id);

    if ( 0 == offset )
    {
        /* this is a new call, start at the beginning */
        smp->local_idx = 0;
        smp->remote_idx = 0;
        smp->proto_idx = 0;
        smp->port_idx = 0;

		atomic_set(&rec_count[tab_id], 0);
    }
    else if ( smp->local_idx >= NSRC_ENTS )
    {
        /* we're done */
        *eof = 1;
        return 0;
    }

    /* now we loop through the tables ... */
    for ( ; smp->local_idx < NSRC_ENTS; smp->local_idx++ )
    {
        /* get the first level entry */
        lip_entry = &lip_tab[tab_id][smp->local_idx];

        /* check if it is active */
        if ( 0 == lip_entry->local_ip )
        {
            /* nope */
            continue;
        }

        for ( ; smp->remote_idx < NDST_ENTS; smp->remote_idx++ )
        {
            /* check if a subset of remote IPs have been used */
            if ( (0 == smp->remote_idx % BITMAP_BITS)
                && (0 == lip_entry->dsts[smp->remote_idx/BITMAP_BITS]) )
            {
                /* nope, we can skip this subset */
                smp->remote_idx += (BITMAP_BITS-1);
                continue;
            }

            /* now check if the local IP uses this specific remote IP */
            if ( 0 == (lip_entry->dsts[smp->remote_idx/BITMAP_BITS] 
                        & (1 << smp->remote_idx % BITMAP_BITS)) )
            {
                /* it isn't, keep moving */
                continue;
            }

            /* get the second level entry */
            rip_entry = &rip_tab[tab_id][smp->remote_idx];

            /* determine our position in dumping */
            if (0 == smp->proto_idx && 0 == smp->port_idx)
            {
                /* this is a new set of ips, lets set it up */

                /* first check if the buffer is big enough for lip/rip/one prt */
                if (buf_idx + sizeof(watch_data_t) + sizeof(watch_port_t) >= buffer_length)
                {
                    /* this buffer isn't big enough, return to caller */
                    *buffer_location = (char *)1;

                    if (debug) printk("insufficient buffer space for data (need %lu@%d, have %d)\n",
                                    sizeof(watch_data_t) + sizeof(watch_port_t), buf_idx, buffer_length);

                    /* fill the remaining buffer with 1s */
                    memset((void *)&buffer[buf_idx], 0xff, buffer_length - buf_idx);
                    //printk("filling buffer with %d bytes of 0xff (idx=%d)\n",
                    //        buffer_length - buf_idx, buf_idx);
                    buf_idx += (buffer_length - buf_idx);

                    return buf_idx;
                }

                /* set up monitor buffer */
                monitor = (watch_data_t *)&buffer[buf_idx];

                /* copy the local, remote IP pair */
                monitor->local_ip = lip_entry->local_ip;
                monitor->remote_ip = rip_entry->remote_ip;
                buf_idx += sizeof(watch_data_t);

		        if (debug) printk("local: 0x%08x\n", lip_entry->local_ip);
			    if (debug) printk("remote: 0x%08x\n", monitor->remote_ip);
            }

            /* now we can just dump, set up port pointer */
            for (; smp->proto_idx < NF_NPROTO; smp->proto_idx++)
            {
                for (; smp->port_idx < NPRT_ENTS; smp->port_idx++ )
                {
                    bitmap = rip_entry->prts[smp->proto_idx][smp->port_idx/BITMAP_BITS];
                    /* check if a subset of ports has been used */
                    if ((0 == smp->port_idx % BITMAP_BITS) && (0 == bitmap))
                    {
                        /* it is not, skip ahead */
                        smp->port_idx += (BITMAP_BITS-1);
                        continue;
                    }

                    /* check if port pair is part of this connection */
                    if (0 == (bitmap & (1 << (smp->port_idx % BITMAP_BITS))))
                    {
                        /* it is not, skip ahead */
                        continue;
                    }

                    /* check if we have the room for this entry */
                    if (buf_idx + sizeof(watch_port_t) >= buffer_length)
                    {
                        /* this buffer isn't big enough, return to caller */
                        *buffer_location = (char *)1;

                        if (debug) printk("insufficient buffer space for ports (need %lu@%d, have %d)\n",
                                        sizeof(watch_port_t), buf_idx, buffer_length);

                        /* fill the remaining buffer with 0s */
                        memset((void *)&buffer[buf_idx], 0xff, buffer_length - buf_idx);
                        buf_idx += (buffer_length - buf_idx);

                        return buf_idx;
                    }

                    /* get the third level entry */
                    prt_entry = &prt_tab[tab_id][smp->proto_idx][smp->port_idx];

                    /* write to file */
                    port = (watch_port_t *)&buffer[buf_idx];
                    port->local_port = prt_entry->local_port;
                    port->remote_port = prt_entry->remote_port;
                    port->npkts[INBOUND] = prt_entry->npkts[INBOUND];
                    port->npkts[OUTBOUND] = prt_entry->npkts[OUTBOUND];
                    port->nbytes[INBOUND] = prt_entry->nbytes[INBOUND];
                    port->nbytes[OUTBOUND] = prt_entry->nbytes[OUTBOUND];
                    port->timestamp= prt_entry->timestamp;
                    port->direction = prt_entry->info_bits & 0xff;
                    port->pad[0] = 0x00;
                    port->pad[1] = 0x00;
                    port->pad[2] = 0x00;
                    buf_idx += sizeof(watch_port_t);

                    /* clear this entry */
                    //memset((void *)prt_entry, 0, sizeof(struct nf_prt_entry));
					atomic_inc(&rec_count[tab_id]);
                }

                if (buf_idx + sizeof(watch_port_t) >= buffer_length)
                {
                    /* this buffer isn't big enough, return to caller */
                    *buffer_location = (char *)1;

                    if (debug) printk("insufficient buffer space for sentinal (need %lu@%d, have %d)\n",
                                    sizeof(watch_port_t), buf_idx, buffer_length);

                    /* fill the remaining buffer with 0s */
                    memset((void *)&buffer[buf_idx], 0xff, buffer_length - buf_idx);
                    buf_idx += (buffer_length - buf_idx);

                    return buf_idx;
                }

                /* insert a sentinal entry (all zeros) */
                memset((void *)&buffer[buf_idx], 0, sizeof(watch_port_t));
                buf_idx += sizeof(watch_port_t);

                /* reset port_idx */
                smp->port_idx = 0;
            }
            /* reset proto_idx */
            smp->proto_idx = 0;

            /* clear this remote IP entry */
            //memset((void *)rip_entry, 0, sizeof(struct nf_rip_entry));
        }
        /* done with the remote IPs */
        /* clear my local IP */
        //memset((void *)lip_entry, 0, sizeof(struct nf_lip_entry));
        smp->remote_idx = 0;
    }
    /* done with the local IPs */
    /* all local IPs should be cleared at this point */

    /* we're done */
    *eof = 1;

    // lock the table
    spin_lock_bh(&tab_lock[tab_id]);
    // clear the tables
    memset((void *)lip_tab[tab_id], 0, 
            sizeof(struct nf_lip_entry)*NSRC_ENTS);
    memset((void *)rip_tab[tab_id], 0,
            sizeof(struct nf_rip_entry)*NDST_ENTS);
    memset((void *)prt_tab[tab_id], 0,
            sizeof(struct nf_prt_entry)*NF_NPROTO*NPRT_ENTS);

	lip_count = atomic_read(&nlip[tab_id]);
	rip_count = atomic_read(&nrip[tab_id]);
	prt_count = atomic_read(&nprt[tab_id]);
	lip_excess = atomic_read(&excess_lip[tab_id]);
	rip_excess = atomic_read(&excess_rip[tab_id]);
	prt_excess = atomic_read(&excess_prt[tab_id]);

	atomic_set(&nlip[tab_id], 0);
	atomic_set(&nrip[tab_id], 0);
	atomic_set(&nprt[tab_id], 0);
	atomic_set(&excess_lip[tab_id], 0);
	atomic_set(&excess_rip[tab_id], 0);
	atomic_set(&excess_prt[tab_id], 0);

    // unlock tables
    spin_unlock_bh(&tab_lock[tab_id]);

	if (lip_count + rip_count + prt_count != 0 
		|| lip_excess + rip_excess + prt_excess != 0)
	{
		printk("pna_mod: {lip_ents:%u, rip_ents:%u, prt_ents:%u}\n",
				lip_count, rip_count, prt_count);
		printk("pna_mod: {lip_excess:%u, rip_excess:%u, prt_excess:%u}\n",
				lip_excess, rip_excess, prt_excess);
	}

	printk("end with %d records (idx exhaust, %d)\n",
			atomic_read(&rec_count[tab_id]), tab_id);

    *buffer_location = (char *)1;
    return buf_idx;
}

