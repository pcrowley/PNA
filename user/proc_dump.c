/**
 * Copyright 2012 Washington University in St Louis
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

/* dumps the in-memory table to a file */
uint64_t mem_dump(int out_fd, void *src, uint64_t table_sz, uint64_t entry_sz)
{
    uint64_t bytes_out, entries;
    char empty[entry_sz];

    /* create null terminator */
    memset(empty, 0, entry_sz);

    /* now we loop through the tables ... */
    entries = 0;
    for (bytes_out = 0; bytes_out < table_sz; bytes_out += entry_sz) {
        /* empty entries are skipped */
        if (0 == memcmp(src+bytes_out, empty, entry_sz)) {
            continue;
        }

		/* write the entry */
        write(out_fd, src+bytes_out, entry_sz);
        entries += 1;
    }

    return entries;
}

/**
 * dump a proc file with `entry_size` byte entries to an existing chunk of
 * memory.
 */
uint64_t proc_dump(int out_fd, char *proc_file, uint64_t entry_size)
{
    int proc_fd;
    struct stat proc_stat;
    uint64_t proc_size;
    uint64_t log_size;
    void *proc_addr;

    /* get the size of the proc file */
    if (stat(proc_file, &proc_stat) != 0) {
        perror("stat proc_file");
        return 0;
    }
    proc_size = proc_stat.st_size;

    /* attempt to proc_open file */
    proc_fd = open(proc_file, O_RDONLY);
    if (proc_fd < 0) {
        if (errno == EACCES) {
            /* EACCES means the file was not used */
            /* we can just skip this round */
            return 0;
        }
        perror("open proc_file");
        return 0;
    }

    /* mmap() for access */
    proc_addr = mmap(NULL, proc_size, PROT_READ, MAP_SHARED, proc_fd, 0);
    if (proc_addr == MAP_FAILED) {
        perror("mmap");
        close(proc_fd);
        return 0;
    }

    log_size = mem_dump(out_fd, proc_addr, proc_size, entry_size);

    /* unmmap() for access */
    if (munmap(proc_addr, proc_size) == -1) {
        perror("munmap");
    }

    /* close file */
    close(proc_fd);

    return log_size;
}
