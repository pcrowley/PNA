
/*
 * UDP send function.  Create a one-off UDP session and send the message.
 */
int send_message(u32 dst_ip, u32 type, u32 data)
{
	int resp;
	struct sockaddr_in dst_addr;
	struct msghdr msg;
	struct iovec iov;
	struct socket *control;
	mm_segment_t oldfs;

	char buffer[MSG_LEN];
	u32 *bufptr;

	/* create the socket */
	resp = sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &control);

	/* connect the socket to a remote host */
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons(CONTROL_PORT);
	dst_addr.sin_addr.s_addr = htonl(dst_ip);

	resp = control->ops->connect(control, (struct sockaddr *)&dst_addr,
								 sizeof(dst_addr), O_RDWR);

	msg.msg_name = &dst_addr;
	msg.msg_namelen = sizeof(dst_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	bufptr = (u32 *)&buffer[0];
	*bufptr = htonl(type);
	bufptr = (u32 *)&buffer[4];
	*bufptr = htonl(data);

	msg.msg_iov->iov_len = MSG_LEN;
	msg.msg_iov->iov_base = &buffer;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	resp = sock_sendmsg(control, &msg, MSG_LEN);
	set_fs(oldfs);

	/* close the socket */
	//control->ops->shutdown(control, 0); // this does not work...
	control->ops->release(control);

	return 0;
}

/*
 * Session action handler.  If a host "acts up," we end up here.
 */
void session_action(int action, u32 src_ip, char *reason)
{
	/* never act on a host that is not in the 192.168.*.* range */
	if ( (src_ip & 0xffff0000) != 0xc0a80000)
	{
		return;
	}

	switch (action)
	{
	case NPR_BLOCK:
		/* send BLOCK message */
		//send_message(src_ip, NPR_BLOCK, src_ip);
		if (debug) printk("Blocked ip 0x%08x (%s)\n", src_ip, reason);
		break;

	case NPR_WHITELIST:
		/* send WHITELIST message */
		//send_message(src_ip, NPR_WHITELIST, src_ip);
		if (debug) printk("Whitelisted packets to ip 0x%08x (%s)\n", src_ip, reason);
		break;
	default:
		/* no action */
		break;
	}
}
