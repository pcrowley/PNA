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
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include "pna_mod.h"

#define DTRIE_PROC_STR "dtrie"

struct pna_dtrie_entry {
  int isprefix;
  unsigned int domain_id;
  struct pna_dtrie_entry* children[2];
};

struct pna_dtrie_entry* pna_dtrie_head;

struct pna_dtrie_entry* pna_dtrie_entry_alloc(void)
{
  struct pna_dtrie_entry* entry = (struct pna_dtrie_entry*)kmalloc(sizeof(struct pna_dtrie_entry), GFP_KERNEL);
  if(!entry)
    return NULL;
  entry->domain_id = 0xFFFFFFFF;
  entry->isprefix = 0;
  memset(entry->children, 0, 2 * sizeof(struct pna_domain_entry*)); 
  return entry;
}



unsigned int pna_dtrie_lookup(unsigned int ip)
{
  unsigned int cur_bit, cur_bit_pos;
  struct pna_dtrie_entry* next_entry;
  struct pna_dtrie_entry* entry = pna_dtrie_head;
  unsigned int curdomain = 0xFFFFFFFF;
  //assume network byte order
  cur_bit_pos = 0;
  cur_bit = (ip >> (31 - cur_bit_pos)) & 0x1;
  next_entry = entry->children[cur_bit];
  while(next_entry){
    entry = next_entry;
    if(entry->isprefix){
      curdomain = entry->domain_id;
    }
    cur_bit_pos ++;
    cur_bit = (ip >> (31 - cur_bit_pos)) & 1;
    next_entry = entry->children[cur_bit]; 
  }
  return curdomain;
}

int pna_dtrie_add(unsigned int prefix, unsigned int max_bit_pos, unsigned int domain_id)
{
  unsigned int cur_bit_pos;
  unsigned int cur_bit;
  struct pna_dtrie_entry* next;
  struct pna_dtrie_entry* cur = pna_dtrie_head;

  printk("pna_dtrie_add %X %i %i\n", prefix, max_bit_pos, domain_id);
  
  cur_bit_pos = 0;
  while(cur_bit_pos < max_bit_pos){
    cur_bit = (prefix >> (31 -  cur_bit_pos)) & 0x1;
    next = cur->children[cur_bit];
    if(!next){
      cur->children[cur_bit] = next = pna_dtrie_entry_alloc();
      if(!next){
        printk("Failed to alloc dtrie entry\n");
        return -1;
      }
    } 
    cur_bit_pos++;
    cur = next;
  }
  cur->isprefix = 1;
  cur->domain_id = domain_id;
  return 0;
}


int dtrie_proc_write(struct file* file, const char* buffer, unsigned long count, void* data)
{
  //reads in 3 unsigned ints, in the order prefix, prefix len, domainid
  unsigned int mybuf[3];
  if (count < (sizeof(unsigned int) * 3)){
    printk("dtrie write too small\n");
    return -EFAULT;
  }
  if(copy_from_user(mybuf, buffer, sizeof(unsigned int) * 3)){
    printk("dtrie write fail");
    return -EFAULT;
  }
  pna_dtrie_add(mybuf[0], mybuf[1], mybuf[2]);
  return count;
}

int pna_dtrie_rm_node(struct pna_dtrie_entry* entry)
{
  if(!entry)
    return 0;
  pna_dtrie_rm_node(entry->children[0]);
  pna_dtrie_rm_node(entry->children[1]);
  kfree(entry);
  return 0;
}

int pna_dtrie_deinit(void)
{
  remove_proc_entry(DTRIE_PROC_STR, proc_parent);
  pna_dtrie_rm_node(pna_dtrie_head);
  printk("pna dtrie freed\n");
  return 0;
}

int pna_dtrie_init(void)
{
  struct proc_dir_entry *dtrie_proc_node;
  pna_dtrie_head = pna_dtrie_entry_alloc();
  if(!pna_dtrie_head){
    printk("failed to init dtrie head\n");
    return -1;
  } 

  dtrie_proc_node = create_proc_entry(DTRIE_PROC_STR, 0644, proc_parent);
  if(!dtrie_proc_node){
    pr_err("failed to make proc entry for %s\n", DTRIE_PROC_STR);
    return -ENOMEM;
  }

  dtrie_proc_node->write_proc = dtrie_proc_write;
  dtrie_proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
  dtrie_proc_node->uid = 0;
  dtrie_proc_node->gid = 0;
  dtrie_proc_node->gid = sizeof(unsigned int)*3;
  
  return 0;
}


