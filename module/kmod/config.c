
/*
 * procfs config function(s)
 */

void set_threshold(int index, unsigned int value)
{
	char *name;

	switch (index)
	{  /* 1 is TCP, 2 is UDP, 3 is ALL */
	case THR_NDSTS:
		name = "ndsts"; break;
	case THR_NPRTS+0:
		name = "ntcp_ports"; break;
	case THR_NPRTS+1:
		name = "nudp_ports"; break;
	case THR_NPRTS+2:
		name = "nall_ports"; break;
	case THR_NBYTES+0:
		name = "ntcp_bytes"; break;
	case THR_NBYTES+1:
		name = "nudpbytes"; break;
	case THR_NBYTES+2:
		name = "nall_bytes"; break;
	case THR_NPKTS+0:
		name = "ntcp_packets"; break;
	case THR_NPKTS+1:
		name = "nudp_packets"; break;
	case THR_NPKTS+2:
		name = "nall_packets"; break;
	case THR_NSESS:
		name = "nsessions"; break;
	default:
		name = "unknown"; break;
	}

	printk("threshold %s set from %u ", name, threshold[index]);

	/* set the value */
	threshold[index] = value;

	printk("to %u\n", threshold[index]);
}

/* get config updates from user */
int config_write(struct file *file, const char *buffer,
                 unsigned long count, void *data)
{
	char kbuffer[PROC_LEN];
	struct cfg_xchange *xchg;

	/* fetch the data from user space to kernel space */
	if ( 0 != copy_from_user(kbuffer, buffer, PROC_LEN) )
	{
		printk("could not copy data from userspace\n");
		return -EFAULT;
	}

	/* otherwise case and use */
	xchg = (struct cfg_xchange *)kbuffer;

	switch (xchg->type)
	{
	case CFG_THR_NDSTS:
		set_threshold(THR_NDSTS, xchg->value);
		break;
	case CFG_THR_NTCPPRTS:
		set_threshold(THR_NPRTS+0, xchg->value);
		break;
	case CFG_THR_NUDPPRTS:
		set_threshold(THR_NPRTS+1, xchg->value);
		break;
	case CFG_THR_NALLPRTS:
		set_threshold(THR_NPRTS+2, xchg->value);
		break;
	case CFG_THR_NTCPBYTES:
		set_threshold(THR_NBYTES+0, xchg->value);
		break;
	case CFG_THR_NUDPBYTES:
		set_threshold(THR_NBYTES+1, xchg->value);
		break;
	case CFG_THR_NALLBYTES:
		set_threshold(THR_NBYTES+2, xchg->value);
		break;
	case CFG_THR_NTCPPKTS:
		set_threshold(THR_NPKTS+0, xchg->value);
		break;
	case CFG_THR_NUDPPKTS:
		set_threshold(THR_NPKTS+1, xchg->value);
		break;
	case CFG_THR_NALLPKTS:
		set_threshold(THR_NPKTS+2, xchg->value);
		break;
	case CFG_THR_NSESS:
		set_threshold(THR_NSESS, xchg->value);
		break;
	case CFG_NET_PREFIX:
		net_prefix = xchg->value;
		printk("set net_prefix to 0x%08x\n", net_prefix);
		break;
	case CFG_NET_MASK:
		net_mask = xchg->value;
		printk("set net_mask to 0x%08x\n", net_mask);
		break;
	default:
		break;
	}

    return PROC_LEN;
}

int config_read(char* buffer, char** buffer_location, off_t offset, 
                int buffer_length, int *eof, void* data)
{
	static int i;
	int ret = 0;
	struct cfg_xchange xchg;

	if ( 0 == offset )
	{
		i = 0;
	}
	else if ( i >= NUM_CFG_PARAMS )
	{
		return 0;
	}

	for ( ; i < NUM_CFG_PARAMS; i++)
	{
		switch (i)
		{
		case CFG_THR_NDSTS: case CFG_THR_NSESS:
		case CFG_THR_NTCPPRTS: case CFG_THR_NUDPPRTS: case CFG_THR_NALLPRTS:
		case CFG_THR_NTCPBYTES: case CFG_THR_NUDPBYTES: case CFG_THR_NALLBYTES:
		case CFG_THR_NTCPPKTS: case CFG_THR_NUDPPKTS: case CFG_THR_NALLPKTS:
			xchg.type = i;
			xchg.value = threshold[i];
			break;
		case CFG_NET_PREFIX:
			xchg.type = i;
			xchg.value = net_prefix;
			break;
		case CFG_NET_MASK:
			xchg.type = i;
			xchg.value = net_mask;
			break;
		default:
			xchg.type = 0;
			xchg.value = 0;
			printk("config dump out of bounds\n");
			break;
		}
		// copy xchg to buffer
		memcpy(&buffer[i*sizeof(struct cfg_xchange)], &xchg, 
			   sizeof(struct cfg_xchange));
		ret += sizeof(struct cfg_xchange);

		/* will the next iteration overflow the buffer? */
		if ( ((i+1) * sizeof(struct cfg_xchange)) >= buffer_length )
		{
			i++;
			*buffer_location = (char *)1; /* needed, but why? */
			return ret;
		}
	}

    *buffer_location = (char *)1; /* needed, but why? */
    return ret;
}
