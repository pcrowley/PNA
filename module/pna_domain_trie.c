/*
Code to peform longest prefix match on an IP and return the domain to
which it belongs.  All inputs must be in network byte order

*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

#define DTRIE_PROC_STR "dtrie"

struct pna_dtrie_entry {
  unsigned int domain_id;
  struct pna_dtrie_entry* children[2];
};

struct pna_dtrie_entry* pna_dtrie_head;

struct pna_dtrie_entry* pna_dtrie_entry_alloc(unsigned int domain_id)
{
  struct pna_dtrie_entry* entry = (struct pna_dtrie_entry*)kmalloc(sizeof(struct pna_dtrie_entry), GFP_KERNEL);
  if(!entry)
    return NULL;
  entry->domain_id = domain_id;
  memset(entry->children, 0, 2 * sizeof(struct pna_domain_entry*)); 
  return entry;
}



struct pna_dtrie_entry* pna_dtrie_getnode(unsigned int ip, unsigned int* cur_bit_pos)
{
  unsigned int cur_bit;
  struct pna_dtrie_entry* next_entry;
  struct pna_dtrie_entry* entry = pna_dtrie_head;
  //assume network byte order
  *cur_bit_pos = 0;
  cur_bit = (ip >> (31 - *cur_bit_pos)) & 0x1;
  next_entry = entry->children[cur_bit];
  while(next_entry){
    entry = next_entry;
    (*cur_bit_pos) ++;
    cur_bit = (ip >> (31 - *cur_bit_pos)) & 1;
    next_entry = entry->children[cur_bit]; 
  }
  return entry;
}

int pna_dtrie_add(unsigned int prefix, unsigned int max_bit_pos, unsigned int domain_id)
{
  unsigned int cur_bit_pos;
  unsigned int cur_bit;
  struct pna_dtrie_entry* next;
  struct pna_dtrie_entry* cur = pna_dtrie_getnode(prefix, &cur_bit_pos);
  
  while(cur_bit_pos < max_bit_pos){
    cur_bit = (prefix >> (31 -  cur_bit_pos)) & 0x1;
    next = pna_dtrie_entry_alloc(cur->domain_id);
    cur->children[cur_bit] = next;
    cur = next; 
    cur_bit_pos++;
  }
  cur->domain_id = domain_id;
  return 0;
}

int pna_dtrie_rm(unsigned int prefix, unsigned int mask)
{
  return 0;
}

unsigned int pna_dtrie_lookup(unsigned int ip)
{
  unsigned int cur_bit_pos = 0;
  return pna_dtrie_getnode(ip, &cur_bit_pos)->domain_id;
}


int dtrie_proc_write(struct file* file, const char* buffer, unsigned long count, void* data)
{
  //reads in 3 unsigned ints, in the order prefix, prefix len, domainid
  unsigned int mybuf[3];
  if (count != (sizeof(unsigned int) * 3)){
    return -ENOMEM;
  }
  if(copy_from_user(mybuf, buffer, count)){
    return -EFAULT;
  }
  pna_dtrie_add(mybuf[0], mybuf[1], mybuf[2]);
  return count;

int pna_dtrie_deinit()
{
  remove_proc_entry(DTRIE_PROC_STR, proc_parent);
  return 0;
}

int pna_dtrie_init()
{
  pna_dtrie_head = pna_dtrie_entry_alloc(0xFFFFFFFF);
  if(!pna_dtrie_head){
    return -1;
  } 

  struct proc_dir_entry *dtrie_proc_node;
  dtrie_proc_node = create_proc_entry(DTRIE_PROC_STR, 0644, proc_parent);
  if(!dtrie_proc_node){
    pr_err("failed to make proc entry for %s\n", DTRIE_PROC_STR);
    return -ENOMEM;
  }

  dtrie_proc_node->write_proc = dtrie_proc_write;
  dtrie_proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
  dtrie_proc_node->uid = 0;
  dtrie_proc_node->gid = 0;
  dtrie_proc_node->gid = 1;
  
/*
  pna_dtrie_add(0x0a0b0000, 16, 1); //10.11.0.0/16
  pna_dtrie_add(0x0a140000, 16, 1); //10.20.0.0 to 10.29.0.0/16
  pna_dtrie_add(0x0a150000, 16, 1);
  pna_dtrie_add(0x0a160000, 16, 1);
  pna_dtrie_add(0x0a170000, 16, 1);
  pna_dtrie_add(0x0a180000, 16, 1);
  pna_dtrie_add(0x0a190000, 16, 1);
  pna_dtrie_add(0x0a1a0000, 16, 1);
  pna_dtrie_add(0x0a1b0000, 16, 1);
  pna_dtrie_add(0x0a1c0000, 16, 1);
  pna_dtrie_add(0x0a1d0000, 16, 1);


  pna_dtrie_add(0x80fc1100, 24, 2); //128.252.17.0/24
  pna_dtrie_add(0x80fcd900, 24, 2); //128.252.217.0/24
  pna_dtrie_add(0x80fcda00, 24, 2); //128.252.218.0/24

  pna_dtrie_add(0x80fc0000, 16, 3); //128.252.0.0/16
  pna_dtrie_add(0xac100000, 12, 3); //172.16.0.0/12
*/
  return 0;
}
