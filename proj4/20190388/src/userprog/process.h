#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool handle_mm_fault(struct vm_entry *vme);
bool verify_stack(void *, void *);
bool expand_stack(void *);
#endif /* userprog/process.h */
