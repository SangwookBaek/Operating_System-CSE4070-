#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"



static void syscall_handler (struct intr_frame *);
void halt(void);
void exit (int );
tid_t exec (const char *);
int wait (tid_t);
int read(int , void*, unsigned);
int write(int, const void *, unsigned);
int check_addr_valid(uint32_t* ,void *);
int fibonacci(int);
int max_of_four_int(int, int, int, int);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t syscall_number;
  uint32_t *pagedir;
  char *file_pointer;
 
  struct thread *cur_thread;
  cur_thread = thread_current();
  pagedir = cur_thread->pagedir;

  // if ((f->esp) >= PHYS_BASE){
  //   exit (-1);
  // }
  
  // pd = pagedir_create();
  // if (pagedir_get_page(pd,f->esp)){
  //   exit(-1);
  // }

  check_addr_valid(pagedir,(f->esp));
  syscall_number = *(uint32_t *)(f->esp);

  switch(syscall_number){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      check_addr_valid(pagedir,(f->esp + 4));
      exit(*(uint32_t *)(f->esp + 4));
      break;
    case SYS_EXEC:
      check_addr_valid(pagedir,(f->esp + 4));
      file_pointer = (char*)(f->esp + 4);
      check_addr_valid(pagedir,*(void **)file_pointer);
      f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_WAIT:
      check_addr_valid(pagedir,(f->esp + 4));
      f->eax = wait((tid_t)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_READ:
      check_addr_valid(pagedir,(f->esp + 4));
      check_addr_valid(pagedir,(f->esp + 8));
      check_addr_valid(pagedir,(f->esp + 12));
      f->eax = read((int)*(uint32_t *)(f->esp+4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
      break;
    case SYS_WRITE:
      check_addr_valid(pagedir,(f->esp + 4));
      check_addr_valid(pagedir,(f->esp + 8));
      check_addr_valid(pagedir,(f->esp + 12));
      f->eax = write((int)*(uint32_t *)(f->esp+4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
      break;


    case SYS_FIBO:
      check_addr_valid(pagedir,(f->esp + 4));
      f->eax = fibonacci((int)*(uint32_t *)(f->esp+4));
      break;
    case SYS_MAXF:
      check_addr_valid(pagedir,(f->esp + 4));
      check_addr_valid(pagedir,(f->esp + 8));
      check_addr_valid(pagedir,(f->esp + 12));
      check_addr_valid(pagedir,(f->esp + 16));

      f->eax = max_of_four_int((int)*(uint32_t *)(f->esp+4), (int)*(uint32_t *)(f->esp + 8), (int)*((uint32_t *)(f->esp + 12)),(int)*((uint32_t *)(f->esp + 16)));
      break;
  }
  // thread_exit ();
}



int fibonacci(int arg1){
  int sum=0;
  for (int i=1;i<=arg1;i++){
    sum += i;
  }
  return sum;
}

int max_of_four_int(int arg1, int arg2, int arg3, int arg4){
  int max = 0;
  if (arg1>=max){
    max = arg1;
  }
  if (arg2 >= max){
    max = arg2;
  }
  if (arg3 >= max){
    max = arg3;
  }
  if (arg4 >= max){
    max = arg4;
  }
  return max;
}


int check_addr_valid(uint32_t *pagedir,void *addr){
 
  if ((addr) >= PHYS_BASE){
    exit (-1);
  }

  if (!pagedir_get_page(pagedir,addr)){
    exit(-1);
  }
  return 1;
}

void halt(void){
  shutdown_power_off();
}


void exit (int status) {
  printf("%s: exit(%d)\n", thread_name(), status);
  struct thread * cur_thread;
  cur_thread = thread_current();
  cur_thread->exit_status = status; //여기서 exit state를 저장을 해줘야함
  thread_exit ();
}

tid_t exec (const char *cmd_line) {
  return process_execute(cmd_line); //여기서 에러체크??
}

int wait (tid_t pid) {
  return process_wait(pid);
}

int read(int fd, void*buffer, unsigned size){
  char ch;
  unsigned read_bytes = 0;
  if (fd==0){
    for (read_bytes =0 ;read_bytes < size;read_bytes++){
      ch = input_getc();
      *(char *)buffer = ch;
      buffer++;
      if (ch == '\0'){
        break;
      }
    }
    return read_bytes;
  }
  return -1;
}

int write(int fd, const void *buffer, unsigned size){
  if (fd ==1){
    putbuf((char *)buffer,size);
    return size;
  }
  return -1;
}
