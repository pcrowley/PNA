/**
 * Copyright 2011 Washington University in St Louis
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

/* PERFORMANCE */
/* taken from linux/jiffies.h in kernel v2.6.21 */
#ifndef time_after_eq64
# define time_after_eq64(a,b) \
   (typecheck(__u64,a) && typecheck(__u64,b) && ((__s64)(a)-(__s64)(b)>=0))
#endif
# define PERF_INTERVAL      10
/* END PERFORMANCE */

/* in-file prototypes */
static void rtmon_clean(unsigned long);

/* external pointers */
extern struct flowtab_info *flowtab_info;
DECLARE_PER_CPU(int, flowtab_idx);

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
#ifdef NSTIME
    unsigned long long ns_min;
    unsigned long long ns_max;
    unsigned long long ns_sum;
#endif /* NSTIME */
    /* end performance counters */

    int (*init)(void);
    int (*hook)(struct pna_flowkey *, int, struct sk_buff *, unsigned long *);
    void (*clean)(void);
    void (*release)(void);
    int (*pipe)(void *);
    char *name;
    int affinity;
    struct task_struct *thread;
    struct pna_queue queue;
};

/* prototypes for pipeline functions */
int rtmon_pipe_start(void *data);
int rtmon_pipe(void *data);

/* a NULL .hook signals the end-of-list */
struct pna_rtmon monitors[] = {
    /* connection monitor */
    { .name = "conmon", .affinity = 3, .thread = NULL, .init = conmon_init,
      .hook = conmon_hook, .clean = conmon_clean, .release = conmon_release,
      .pipe = rtmon_pipe_start },
    /* local IP monitor */
    { .name = "lipmon", .affinity = 1, .thread = NULL, .init = lipmon_init,
      .hook = lipmon_hook, .clean = lipmon_clean, .release = lipmon_release,
      .pipe = rtmon_pipe },
    /* NULL hook entry is end of list delimited */
    { .name = "null", .affinity = 0, .thread = NULL, .init = NULL,
      .hook = NULL, .clean = NULL, .release = NULL, .pipe = NULL }
};

/* timer for calling clean function */
DEFINE_TIMER(clean_timer, rtmon_clean, 0, 0);

/* PNA pipeline queue initialization routine */
void pna_queue_init(struct pna_rtmon *monitor)
{
    memset(&monitor->queue, 0, sizeof(struct pna_queue));
}

/**
 * PNA queue item insertion routine
 * @return 0 if there was no room for insertion
 */
int pna_enqueue(struct pna_queue *queue, struct pna_pipedata *data, struct pna_rtmon *next)
{
#if QUEUE_TYPE == QUEUE_TYPE_MCBUF
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
        if (next != NULL) {
            wake_up_process(next->thread);
        }
    }
    return 1;
#elif QUEUE_TYPE == QUEUE_TYPE_CIRC
    /* producer */
    int next;
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
#endif /* QUEUE_TYPE */
}

/**
 * PNA queue removal routine 
 * @return 0 if there is nothing to dequeue
 */
int pna_dequeue(struct pna_queue *queue, struct pna_pipedata *data)
{
#if QUEUE_TYPE == QUEUE_TYPE_MCBUF
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
#endif /* QUEUE_TYPE */
}

int rtmon_pipe_monitor(struct pna_rtmon *self, struct pna_pipedata *data)
{
    int ret;

    /* PERFORMANCE */
    __u32 t_interval;
    __u32 fps_in, Mbps_in, avg_in;
    __u32 fps_out, Mbps_out, avg_out;
    struct sk_buff *skb = data->skb;
    /* END PERFORMANCE */

#ifdef NSTIME
    struct timespec start, stop;
    unsigned long long ns_diff;
    getnstimeofday(&start);
#endif /* NSTIME */

    /* process in hook --- only important thing here... */
    ret = self->hook(&data->key, data->direction, skb, &data->data);

#ifdef NSTIME
    getnstimeofday(&stop);
    ns_diff = ((stop.tv_sec - start.tv_sec) * 1000000000);
    ns_diff += (stop.tv_nsec - start.tv_nsec);

    self->ns_sum += ns_diff;
    if (ns_diff < self->ns_min) {
        self->ns_min = ns_diff;
    }
    if (ns_diff > self->ns_max) {
        self->ns_max = ns_diff;
    }
#endif /* NSTIME */

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
            avg_in -= (ETH_INTERFRAME_GAP + ETH_PREAMBLE);
        }

        fps_out = self->p_interval[PNA_DIR_OUTBOUND] / t_interval;
        /* 125000 Mb = (1000 MB/KB * 1000 KB/B) / 8 bits/B */
        Mbps_out = self->B_interval[PNA_DIR_OUTBOUND] / 125000 / t_interval;
        avg_out = 0;
        if (self->p_interval[PNA_DIR_OUTBOUND] != 0) {
            avg_out = self->B_interval[PNA_DIR_OUTBOUND];
            avg_out /= self->p_interval[PNA_DIR_OUTBOUND];
            avg_out -= (ETH_INTERFRAME_GAP + ETH_PREAMBLE);
        }
        /* report the numbers */
        if (fps_in + fps_out > 1000) {
            pr_info("pna smpid:%d,%s_in_fps:%u,%s_in_Mbps:%u,%s_in_avg:%u,"
                    "%s_out_fps:%u,%s_out_Mbps:%u,%s_out_avg:%u\n",
                    smp_processor_id(), self->name,fps_in, self->name, Mbps_in,
                    self->name, avg_in, self->name, fps_out, self->name,
                    Mbps_out, self->name, avg_out);
#ifdef NSTIME
            pr_info("pna %s time:{min:%llu,avg:%llu,max:%llu}\n", self->name,
                    self->ns_min,
                    self->ns_sum /
                        (self->p_interval[PNA_DIR_OUTBOUND]+self->p_interval[PNA_DIR_INBOUND]),
                    self->ns_max);
#endif /* NSTIME */
        }

#ifdef NSTIME
        self->ns_sum = 0;
        self->ns_min = -1;
        self->ns_max = 0;
#endif /* NSTIME */

        /* reset updated counters */
        self->p_interval[PNA_DIR_INBOUND] = 0;
        self->B_interval[PNA_DIR_INBOUND] = 0;
        self->p_interval[PNA_DIR_OUTBOUND] = 0;
        self->B_interval[PNA_DIR_OUTBOUND] = 0;
        self->t_jiffies = msecs_to_jiffies(PERF_INTERVAL*MSEC_PER_SEC);
        self->t_jiffies += get_jiffies_64();
    }

    /* increment packets seen in this interval */
    self->p_interval[data->direction]++;
    self->B_interval[data->direction] += skb->len + ETH_OVERHEAD;
    /* END PERFORMANCE counters */

    return ret;
}

/* "start" pipeline wrapper to combine multiple queues from flow monitor */
int rtmon_pipe_start(void *data)
{
    int i, ret, processed;
    struct pna_pipedata piped;
    struct flowtab_info *info;
    struct pna_rtmon *self = data;
    struct pna_rtmon *next = self+1;

    /* loop until we get a stop signal */
    while (!kthread_should_stop()) {
        processed = 0;

        /* combine data from n flow tables */
        for (i = 0; i < pna_tables; i++) {
            info = &flowtab_info[i];
            while (0 != pna_dequeue(&info->queue, &piped)) {
                if (kthread_should_stop()) {
                    i = pna_tables;
                    break;
                }
                /* process the data */
                rtmon_pipe_monitor(self, &piped);
                processed++;

                /* ready the next "stage" */
                if (next->pipe == NULL) {
                    /* finish processing */
                    kfree_skb(piped.skb);
                }
                else {
                    /* put new data into buffer */
                    ret = pna_enqueue(&next->queue, &piped, next);
                    if (ret == 0) {
                        pr_info("fifo overflow (%s)\n", self->name);
                    }
                }
            }
        }

        set_current_state(TASK_INTERRUPTIBLE);
        if (processed == 0 && !kthread_should_stop()) {
            /* no work, take a break */
            schedule();
        }
        __set_current_state(TASK_RUNNING);
    }

    return 0;
}

/* connection monitor pipe wrapper for hook */
int rtmon_pipe(void *data)
{
    int ret;
    struct pna_pipedata piped;
    struct pna_rtmon *self = data;
    struct pna_rtmon *next = self+1;

    /* loop until we get a stop signal */
    while (!kthread_should_stop()) {
        /* try to fetch data from buffer */
        set_current_state(TASK_INTERRUPTIBLE);
        if (pna_dequeue(&self->queue, &piped) == 0) {
            /* no work, take a break */
            schedule();
            continue;
        }
        __set_current_state(TASK_RUNNING);

        /* process the data */
        rtmon_pipe_monitor(self, &piped);

        /* ready the next "stage" */
        if (next->pipe == NULL) {
            /* finish processing */
            kfree_skb(piped.skb);
        }
        else {
            /* put new data into buffer */
            ret = pna_enqueue(&next->queue, &piped, next);
            if (ret == 0) {
                pr_info("fifo overflow (%s)\n", self->name);
            }
        }
    }

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
int rtmon_hook(struct pna_flowkey key, int direction, struct sk_buff *skb,
               unsigned long data)
{
    int ret;
#ifdef PIPELINE_MODE
    int idx;
    struct flowtab_info *info;
    struct pna_pipedata piped = { .key = key, 
        .direction = direction, .skb = skb, .data = data };

    idx = get_cpu_var(flowtab_idx);
    info = &flowtab_info[idx];

    /* enqueue data to flow tab, will be dequeued in pipeline */
    ret = pna_enqueue(&info->queue, &piped, &monitors[0]);
    if (ret == 0) {
        pr_info("fifo overflow (flowtab%d)\n", idx);
    }
#else 
    struct pna_rtmon *monitor = &monitors[0];

    for ( ; monitor->hook != NULL; monitor++) {
        ret = monitor->hook(&key, direction, skb, &data);
    }
#endif /* PIPELINE_MODE */

    return 0;
}

/* initialize all the resources needed for each rtmon */
int rtmon_init(void)
{
#ifdef PIPELINE_MODE
    int i;
    struct task_struct *t;
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
    for (i = 0; i < sizeof(monitors)/sizeof(struct pna_rtmon); i++) {
        monitor = &monitors[i];
        /* check if this monitor is pipeline-aware */
        if (monitor->pipe == NULL) {
            monitor->thread = NULL;
            break;
        }

        /* ready the queue for this stage */
        pna_queue_init(monitor);

        /* create the kernel thread */
        t = kthread_create(monitor->pipe, monitor, 
                "pna_%s/%d", monitor->name, monitor->affinity);
        if (IS_ERR(t)) {
            pr_err("pna: failed to start rtmon thread on %d\n",
                   monitor->affinity);
        }

        /* assign to distinct CPU */
        kthread_bind(t, monitor->affinity);
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
