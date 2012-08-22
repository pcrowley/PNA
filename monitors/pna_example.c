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

/**
 * Example PNA monitor.
 * This example is simple so it doesn't use the .init() or .release()
 * callbacks.  It does create a variable called "sample_freq" which should be
 * available under /sys/module/pna/parameters/sample_freq.
 * 
 * All the monitor does is print out some information for 1 out of every
 * sample_freq packets.
 */
/* functions: example_hook, example_clean */
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/hash.h>
#include <linux/in.h>

#include "pna.h"
#include "pna_module.h"

MODULE_LICENSE("Apache 2.0");
MODULE_AUTHOR("Michael J. Schultz <mjschultz@gmail.com>");

uint sample_freq = 100;
PNA_PARAM(uint, sample_freq, "Frequency at which to print out packets");

int example_hook(struct session_key *, int, struct sk_buff *, unsigned long *);
void example_clean(void);

struct pna_rtmon example = {
    .name = "Example monitor",
    //.init = example_init,       /**< allocate resource on load */
    .hook = example_hook,         /**< called for every packet PNA sees */
    .clean = example_clean,       /**< periodic maintenance callback */
    //.release = example_release, /**< release resource on unload */
};
PNA_MONITOR(&example);

int example_hook(struct session_key *key, int direction, struct sk_buff *skb,
                unsigned long *data)
{
    static int index = 0;

    if (index++ == sample_freq) {
        index = 0;
        pna_info("example: local 0x%08x:%d, remote 0x%08x:%d\n",
                key->local_ip, key->local_port,
                key->remote_ip, key->remote_port);
    }

    return 0;
}

void example_clean(void)
{
    pna_info("pna_example: periodic callback\n");
}
