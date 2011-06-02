/* real-time hook system */
/* @functions: rtmon_init, rtmon_hook, rtmon_clean, rtmon_release */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/cpu.h>
#include <linux/kthread.h>
#include <linux/wait.h>

#include <linux/kfifo.h>
#include <linux/prefetch.h>
#include <linux/circ_buf.h>

#include "pna.h"

/**
 * Inter-stage queue settings
 *****/
#define QUEUE_TYPE_KFIFO 1
#define QUEUE_TYPE_CIRC  2
#define QUEUE_TYPE_MCBUF 3

#define QUEUE_TYPE QUEUE_TYPE_MCBUF
/*****/

/* in-file prototypes */
static void rtmon_clean(unsigned long);

struct pna_pipedata {
    struct pna_flowkey *key;    /* 8 */
    int direction;              /* 4 */
    struct sk_buff *skb;        /* 8 */
    unsigned long data;         /* 8 */
} ____cacheline_aligned;
#define PNA_QUEUE_SZ (2<<8)

#define PNA_QUEUE_BATCH_SZ (PNA_QUEUE_SZ>>2)
#define PNA_QUEUE_NEXT(x) (((x) + 1) & (PNA_QUEUE_SZ - 1))

/* PERFORMANCE */
/* taken from linux/jiffies.h in kernel v2.6.21 */
#ifndef time_after_eq64
# define time_after_eq64(a,b) \
   (typecheck(__u64,a) && typecheck(__u64,b) && ((__s64)(a)-(__s64)(b)>=0))
#endif
# define ETH_INTERFRAME_GAP 12   /* 9.6ms @ 1Gbps */
# define ETH_PREAMBLE       8    /* preamble + start-of-frame delimiter */
# define ETH_OVERHEAD       (ETH_INTERFRAME_GAP + ETH_PREAMBLE)
# define PERF_INTERVAL      10
/* END PERFORMANCE */

#if QUEUE_TYPE == QUEUE_TYPE_CIRC
struct pna_queue {
    int head ____cacheline_aligned;
    int tail ____cacheline_aligned;
    struct pna_pipedata data[PNA_QUEUE_SZ];
};
#elif QUEUE_TYPE == QUEUE_TYPE_MCBUF
struct pna_queue {
    /* shared control variables */
    volatile int tail ____cacheline_aligned;
    volatile int head;

    /* consumer's local variables */
    int reader_head ____cacheline_aligned;
    int reader_next;
    int reader_batch;

    /* producer's local variables */
    int writer_tail ____cacheline_aligned;
    int writer_next;
    int writer_batch;

    /* buffer data */
    struct pna_pipedata data[PNA_QUEUE_SZ];
};
#endif /* QUEUE_TYPE */

/*
 * @init: initialization routine for a hook
 * @hook: hook function called on every packet
 * @clean: clean function called periodically to reset tables/counters
 * @release: take-down function for table data and cleanup
 * @pipe: wrapper to @hook used in pipeline mode
 */
struct pna_rtmon {
    /* performance counters */
    __u64 t_jiffies; /* 8 */
    struct timeval currtime; /* 8 */
    struct timeval prevtime; /* 8 */
    __u32 p_interval[PNA_DIRECTIONS]; /* 8 */
    __u32 B_interval[PNA_DIRECTIONS]; /* 8 */
    /* end performance counters */

    int (*init)(void);
    int (*hook)(struct pna_flowkey *, int, struct sk_buff *, unsigned long *);
    void (*clean)(void);
    void (*release)(void);
    int (*pipe)(void *);
    char *name;
    struct task_struct *thread;
#if (QUEUE_TYPE == QUEUE_TYPE_CIRC) || (QUEUE_TYPE == QUEUE_TYPE_MCBUF)
    struct pna_queue queue;
#elif QUEUE_TYPE == QUEUE_TYPE_KFIFO
    DECLARE_KFIFO(queue, struct pna_pipedata, PNA_QUEUE_SZ);
#endif /* QUEUE_TYPE */
};

/* prototypes for pipeline functions */
int rtmon_pipe(void *data);

/* a NULL .hook signals the end-of-list */
struct pna_rtmon monitors[] = {
    /* connection monitor */
    { .name = "conmon", .thread = NULL, .init = conmon_init,
      .hook = conmon_hook, .clean = conmon_clean, .release = conmon_release,
      .pipe = rtmon_pipe },
    /* local IP monitor */
    { .name = "lipmon", .thread = NULL, .init = lipmon_init,
      .hook = lipmon_hook, .clean = lipmon_clean, .release = lipmon_release,
      .pipe = rtmon_pipe },
    /* NULL hook entry is end of list delimited */
    { .name = "null", .thread = NULL, .init = NULL, .hook = NULL,
      .clean = NULL, .release = NULL, .pipe = NULL }
};

/* timer for calling clean function */
DEFINE_TIMER(clean_timer, rtmon_clean, 0, 0);

/* PNA pipeline queue initialization routine */
void pna_queue_init(struct pna_rtmon *monitor)
{
#if (QUEUE_TYPE == QUEUE_TYPE_CIRC) || (QUEUE_TYPE == QUEUE_TYPE_MCBUF)
    memset(&monitor->queue, 0, sizeof(struct pna_queue));
#elif QUEUE_TYPE == QUEUE_TYPE_KFIFO
    INIT_KFIFO(monitor->queue);
#endif /* QUEUE_TYPE */
}

/**
 * PNA queue item insertion routine
 * @return 0 if there was no room for insertion
 */
int pna_enqueue(struct pna_rtmon *monitor, struct pna_pipedata *data)
{
#if QUEUE_TYPE == QUEUE_TYPE_MCBUF
    struct pna_queue *queue = &monitor->queue;
    int next_writer_tail = PNA_QUEUE_NEXT(queue->writer_next);

    if (next_writer_tail == queue->writer_tail) {
        if (next_writer_tail == queue->tail) {
            return 0;
        }
        queue->writer_tail = queue->tail;
    }
    queue->data[queue->writer_next] = *data;
    queue->writer_next = next_writer_tail;
    queue->writer_batch++;
    if (queue->writer_batch >= PNA_QUEUE_BATCH_SZ) {
        queue->head = queue->writer_next;
        queue->writer_batch = 0;
    }
    return 1;
#elif QUEUE_TYPE == QUEUE_TYPE_CIRC
    /* producer */
    int next;
    struct pna_queue *queue = &monitor->queue;
    int head = queue->head;
    int tail = ACCESS_ONCE(queue->tail);

    if (CIRC_SPACE(head, tail, PNA_QUEUE_SZ) >= 1) {
        /* insert item into data buffer */
        memcpy(&queue->data[head], data, sizeof(struct pna_pipedata));

        next = (head + 1) & (PNA_QUEUE_SZ - 1);
        smp_wmb(); /* commit item before incrementing head */
        queue->head = next;
        prefetchw(&queue->data[head]);
    }
    else {
        /* nothing could be inserted */
        return 0;
    }

    return 1;
#elif QUEUE_TYPE == QUEUE_TYPE_KFIFO
    return kfifo_put(&monitor->queue, data);
#endif /* QUEUE_TYPE */
}

/**
 * PNA queue removal routine 
 * @return 0 if there is nothing to dequeue
 */
int pna_dequeue(struct pna_rtmon *monitor, struct pna_pipedata *data)
{
#if QUEUE_TYPE == QUEUE_TYPE_MCBUF
    struct pna_queue *queue = &monitor->queue;

    if (queue->reader_next == queue->reader_head) {
        if (queue->reader_next == queue->head) {
            return 0;
        }
        queue->reader_head = queue->head;
    }

    *data = queue->data[queue->reader_next];
    queue->reader_next = PNA_QUEUE_NEXT(queue->reader_next);
    queue->reader_batch++;
    if (queue->reader_batch >= PNA_QUEUE_BATCH_SZ) {
        queue->tail = queue->reader_next;
        queue->reader_batch = 0;
    }

    return 1;
#elif QUEUE_TYPE == QUEUE_TYPE_CIRC
    struct pna_queue *queue = &monitor->queue;
    int head = ACCESS_ONCE(queue->head);
    int tail = queue->tail;

    if (CIRC_CNT(head, tail, PNA_QUEUE_SZ) >= 1) {
        /* make sure we read tail before reading contents at tail */
        smp_read_barrier_depends();

        /* read the item from tail */
        memcpy(data, &queue->data[tail], sizeof(struct pna_pipedata));

        /* make sure tail is read *before* moving tail */
        smp_mb();

        queue->tail = (tail + 1 ) & (PNA_QUEUE_SZ - 1);
    }
    else {
        /* nothing to be returned */
        return 0;
    }

    return 1;
#elif QUEUE_TYPE == QUEUE_TYPE_KFIFO
    return kfifo_get(&monitor->queue, data);
#endif /* QUEUE_TYPE */
}

/* connection monitor pipe wrapper for hook */
int rtmon_pipe(void *data)
{
    /* PERFORMANCE */
    __u32 t_interval;
    __u32 fps_in, Mbps_in, avg_in;
    __u32 fps_out, Mbps_out, avg_out;
    /* END PERFORMANCE */
    int ret;
    struct pna_pipedata piped;
    struct pna_rtmon *self = data;
    struct pna_rtmon *next = self+1;

    /* loop until we get a stop signal */
    while (!kthread_should_stop()) {
        /* try to fetch data from buffer */
        if (pna_dequeue(self, &piped) == 0) {
            /* no work, take a break */
            schedule();
            continue;
        }

        /* process in hook */
        ret = self->hook(piped.key, piped.direction, piped.skb, &piped.data);

        /* PERFORMANCE: packet throughput */
        if ( time_after_eq64(get_jiffies_64(), self->t_jiffies) ) {
            /* get sampling interval time */
            do_gettimeofday(&self->currtime);
            t_interval = self->currtime.tv_sec - self->prevtime.tv_sec;
            /* update for next round */
            self->prevtime = self->currtime;

            /* calculate the numbers */
            fps_in = self->p_interval[PNA_DIR_INBOUND] / t_interval;
            /* 125000 Mb = (1000 MB/KB * 1000 KB/B) / 8 bits/B */
            Mbps_in = self->B_interval[PNA_DIR_INBOUND] / 125000 / t_interval;
            avg_in = 0;
            if (self->p_interval[PNA_DIR_INBOUND] != 0) {
                avg_in = self->B_interval[PNA_DIR_INBOUND];
                avg_in /= self->p_interval[PNA_DIR_INBOUND];
                avg_in -= ETH_OVERHEAD;
            }

            fps_out = self->p_interval[PNA_DIR_OUTBOUND] / t_interval;
            /* 125000 Mb = (1000 MB/KB * 1000 KB/B) / 8 bits/B */
            Mbps_out = self->B_interval[PNA_DIR_OUTBOUND] / 125000 / t_interval;
            avg_out = 0;
            if (self->p_interval[PNA_DIR_OUTBOUND] != 0) {
                avg_out = self->B_interval[PNA_DIR_OUTBOUND];
                avg_out /= self->p_interval[PNA_DIR_OUTBOUND];
                avg_out -= ETH_OVERHEAD;
            }
            /* report the numbers */
            if (fps_in + fps_out > 1000) {
                pr_info("pna %s smpid:%d, " "in:{fps:%u,Mbps:%u,avg:%u}, "
                        "out:{fps:%u,Mbps:%u,avg:%u}\n", self->name,
                        smp_processor_id(), fps_in, Mbps_in, avg_in,
                        fps_out, Mbps_out, avg_out);
            }

            /* reset updated counters */
            self->p_interval[PNA_DIR_INBOUND] = 0;
            self->B_interval[PNA_DIR_INBOUND] = 0;
            self->p_interval[PNA_DIR_OUTBOUND] = 0;
            self->B_interval[PNA_DIR_OUTBOUND] = 0;
            self->t_jiffies = msecs_to_jiffies(PERF_INTERVAL*MSEC_PER_SEC);
            self->t_jiffies += get_jiffies_64();
        }

        /* increment packets seen in this interval */
        self->p_interval[piped.direction]++;
        self->B_interval[piped.direction] += (piped.skb->tail-piped.skb->mac_header) + ETH_OVERHEAD;
        /* END PERFORMANCE counters */

        if (next->pipe == NULL) {
            /* finish processing */
            kfree_skb(piped.skb);
        }
        else {
            /* put new data into buffer */
            ret = pna_enqueue(next, &piped);
            if (ret == 0) {
                pr_info("fifo overflow (%s)\n", self->name);
            }
        }
    }

    /* dump stats */
    pr_info("pna_%s {invcsw:%ld,vcsw:%ld}\n", self->name, current->nivcsw, current->nvcsw);


    return 0;
}

/* reset each rtmon for next round of processing -- once per */
static void rtmon_clean(unsigned long data)
{
    struct pna_rtmon *monitor;

    for (monitor = &monitors[0]; monitor->hook != NULL; monitor++) {
        monitor->clean();
    }

    /* update the timer for the next round */
    mod_timer(&clean_timer, jiffies + msecs_to_jiffies(RTMON_CLEAN_INTERVAL));
}

/* hook from main on packet to start real-time monitoring */
int rtmon_hook(struct pna_flowkey *key, int direction, struct sk_buff *skb,
               unsigned long data)
{
    int ret;
    struct pna_rtmon *monitor = &monitors[0];

#ifdef PIPELINE_MODE
    struct pna_pipedata piped = { .key = key, 
        .direction = direction, .skb = skb, .data = data };

    /* start the pipeline */
    ret = pna_enqueue(monitor, &piped);
    if (ret == 0) {
        pr_info("fifo overflow (start)\n");
    }
#else 
    for ( ; monitor->hook != NULL; monitor++) {
        ret = monitor->hook(key, direction, skb, &data);
    }
#endif /* PIPELINE_MODE */

    return 0;
}

/* initialize all the resources needed for each rtmon */
int rtmon_init(void)
{
#ifdef PIPELINE_MODE
    int i, cpu;
    struct task_struct *t;
    int cpu_count = num_active_cpus();
#endif /* PIPELINE_MODE */
    int ret = 0;

    struct pna_rtmon *monitor;
    for (monitor = &monitors[0]; monitor->hook != NULL; monitor++) {
        ret += monitor->init();
    }

    /* initialize/correct timer */
    init_timer(&clean_timer);
    clean_timer.expires = jiffies + msecs_to_jiffies(RTMON_CLEAN_INTERVAL);
    add_timer(&clean_timer);

#ifdef PIPELINE_MODE
    /* start up the pipe monitors */
    cpu = (cpu_count - 1) % cpu_count; // highest CPU is for flowmon
    for (i = 0; i < sizeof(monitors)/sizeof(struct pna_rtmon); i++) {
        monitor = &monitors[i];
        /* check if this monitor is pipeline-aware */
        if (monitor->pipe == NULL) {
            monitor->thread = NULL;
            break;
        }

        /* assign to next core on same processor */
        cpu = (cpu - 2) % cpu_count;

        /* ready the queue for this stage */
        pna_queue_init(monitor);

        /* create the kernel thread */
        t = kthread_create(monitor->pipe, monitor, 
                "pna_%s/%d", monitor->name, cpu);
        if (IS_ERR(t)) {
            pr_err("pna: failed to start rtmon thread on %d\n", cpu);
        }

        /* assign to distinct CPU */
        kthread_bind(t, cpu);
        monitor->thread = t;

        /* start the kthread */
        wake_up_process(t);
    }
#endif /* PIPELINE_MODE */

    return ret;
}

/* release the resources each rtmon is using */
void rtmon_release(void)
{
    struct pna_rtmon *monitor;

#ifdef PIPELINE_MODE
    /* stop pipeline monitors */
    for (monitor = &monitors[0]; monitor->thread != NULL; monitor++) {
        kthread_stop(monitor->thread);
        monitor->thread = NULL;
    }
#endif /* PIPELINE_MODE */

    /* remove the timer */
    del_timer(&clean_timer);

    /* clean up each of the monitors */
    for (monitor = &monitors[0]; monitor->hook != NULL; monitor++) {
        monitor->release();
    }
}
