#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

extern struct lock file_lock;
void exit (int status);

#endif /* userprog/syscall.h */
