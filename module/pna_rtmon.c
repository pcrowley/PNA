/* real-time hook system */
/* @functions: rtmon_init, rtmon_hook, rtmon_clean, rtmon_release */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/cpu.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/kfifo.h>

#include "pna.h"

/* in-file prototypes */
static void rtmon_clean(unsigned long);

struct pna_pipedata {
    struct pna_flowkey *key;
    int direction;
    struct sk_buff *skb;
    unsigned long data;
};
#define PNA_RTMON_FIFO_SZ (16)

/*
 * @init: initialization routine for a hook
 * @hook: hook function called on every packet
 * @clean: clean function called periodically to reset tables/counters
 * @release: take-down function for table data and cleanup
 * @pipe: wrapper to @hook used in pipeline mode
 */
struct pna_rtmon {
    int (*init)(void);
    int (*hook)(struct pna_flowkey *, int, struct sk_buff *, unsigned long *);
    void (*clean)(void);
    void (*release)(void);
    int (*pipe)(void *);
    char *name;
    struct task_struct *thread;
    wait_queue_head_t event;
    DECLARE_KFIFO(queue, struct pna_pipedata, PNA_RTMON_FIFO_SZ);
};

/* prototypes for pipeline functions */
int rtmon_pipe(void *data);
int rtmon_pipe_end(void *data);

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
      .clean = NULL, .release = NULL, .pipe = rtmon_pipe_end }
};

/* timer for calling clean function */
DEFINE_TIMER(clean_timer, rtmon_clean, 0, 0);

/* connection monitor pipe wrapper for hook */
int rtmon_pipe(void *data)
{
    int ret;
    struct pna_pipedata piped;
    struct pna_rtmon *self = data;
    struct pna_rtmon *next = self+1;

    /* loop until we get a stop signal */
    while (!kthread_should_stop()) {
        wait_event_interruptible(self->event, kthread_should_stop() ||
                !kfifo_is_empty(&self->queue));
        if (kthread_should_stop()) {
            break;
        }

        /* fetch data from buffer */
        ret = kfifo_get(&self->queue, &piped);
        if (ret != 0) {
            pr_info("fifo underflow (%s)\n", self->name);
        }

        /* process in hook */
        ret = self->hook(piped.key, piped.direction, piped.skb, &piped.data);

        /* put new data into buffer */
        ret = kfifo_put(&next->queue, &piped);
        if (ret != 0) {
            pr_info("fifo overflow (%s)\n", self->name);
        }

        /* push to next pipe */
        wake_up_interruptible_all(&next->event);
    }

    return 0;
}

/* pipe function completes per-packet processing */
int rtmon_pipe_end(void *data)
{
    int ret;
    struct pna_pipedata piped;
    struct pna_rtmon *self = data;

    /* loop until we get a stop signal */
    while (!kthread_should_stop()) {
        wait_event_interruptible(self->event, kthread_should_stop() ||
                !kfifo_is_empty(&self->queue));
        if (kthread_should_stop()) {
            break;
        }

        /* fetch data from buffer */
        piped.skb = NULL;
        ret = kfifo_get(&self->queue, &piped);
        if (ret != 0) {
            pr_info("fifo underflow (%s)\n", self->name);
        }

        /* finish processing */
        kfree_skb(piped.skb);
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
int rtmon_hook(struct pna_flowkey *key, int direction, struct sk_buff *skb,
               unsigned long data)
{
    int ret;
    struct pna_rtmon *monitor = &monitors[0];

#ifndef PIPELINE_MODE
    struct pna_pipedata piped;
    piped.key = key;
    piped.direction = direction;
    piped.skb = skb;
    piped.data = data;
    //piped = { .key = key, .direction = direction, .skb = skb, .data = data };

    /* start the pipeline */
    ret = kfifo_put(&monitor->queue, &piped);
    if (ret != 0) {
        pr_info("fifo overflow\n");
    }
    wake_up_interruptible_all(&monitor->event);
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
    int cpu;
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
    cpu = (cpu_count - 1) % cpu_count;
    for (monitor = &monitors[0]; monitor->hook != NULL; monitor++) {
        cpu = (cpu - 1) % cpu_count;

        /* ready the event queue and FIFO for this stage */
        init_waitqueue_head(&monitor->event);
        INIT_KFIFO(monitor->queue);

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
