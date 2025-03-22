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
#include "filesys/file.h"
#include "filesys/filesys.h"


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
int open(const char *file);
int filesize(int fd);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);

void check_file_null (const char *file);

struct lock file_lock;

void
syscall_init (void) 
{
  lock_init(&file_lock);
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

    case SYS_CREATE:
      check_addr_valid(pagedir,(f->esp + 4));
      check_addr_valid(pagedir,(f->esp + 8));
      check_file_null ((const char *)*(uint32_t *)(f->esp + 4));
      file_pointer = (char*)(f->esp + 4);
      check_addr_valid(pagedir,*(void **)file_pointer);
      f->eax = create((const char *)*(uint32_t *)(f->esp + 4),(unsigned)*(uint32_t *)(f->esp + 8));
      break;

    case SYS_REMOVE:
      check_addr_valid(pagedir,(f->esp + 4));
      check_file_null ((const char *)*(uint32_t *)(f->esp + 4));
      file_pointer = (char*)(f->esp + 4);
      check_addr_valid(pagedir,*(void **)file_pointer);
      f->eax = remove((const char *)*(uint32_t *)(f->esp + 4));
      break;


    case SYS_OPEN:
      check_addr_valid(pagedir,(f->esp + 4));
      file_pointer = (char*)(f->esp + 4);
      check_addr_valid(pagedir,*(void **)file_pointer);
      check_file_null ((const char *)*(uint32_t *)(f->esp + 4));
      f->eax = open((const char*)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_FILESIZE:
      check_addr_valid(pagedir,(f->esp + 4));
      f->eax = filesize((int)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_READ:
      check_addr_valid(pagedir,(f->esp + 4));
      check_addr_valid(pagedir,(f->esp + 8));
      check_addr_valid(pagedir,(f->esp + 12));
      file_pointer = (char*)(f->esp + 8);
      check_addr_valid(pagedir,*(void **)file_pointer);
      f->eax = read((int)*(uint32_t *)(f->esp+4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
      break;

    case SYS_WRITE:
      check_addr_valid(pagedir,(f->esp + 4));
      check_addr_valid(pagedir,(f->esp + 8));
      check_addr_valid(pagedir,(f->esp + 12));
      file_pointer = (char*)(f->esp + 8);
      check_addr_valid(pagedir,*(void **)file_pointer);
      f->eax = write((int)*(uint32_t *)(f->esp+4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
      break;
    
    case SYS_SEEK:
      check_addr_valid(pagedir,(f->esp + 4));
      check_addr_valid(pagedir,(f->esp + 8));
      seek((int)*(uint32_t *)(f->esp+4),(unsigned)*(uint32_t *)(f->esp+8));
      break;

    case SYS_TELL:
      check_addr_valid(pagedir,(f->esp + 4));
      f->eax = tell ((int)*(uint32_t *)(f->esp+4));
      break;

    case SYS_CLOSE:
      check_addr_valid(pagedir,(f->esp + 4));
      close((int)*(uint32_t *)(f->esp+4));
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

void check_file_null (const char *file){
  if (file==NULL){
    exit(-1);
  }
}


bool create (const char *file, unsigned initial_size){

  return filesys_create(file,initial_size);
}

bool remove (const char *file){
  // if (file == NULL) {
  //     exit(-1);
  // }
  return filesys_remove(file);
}

int open(const char *file){
  struct file *file_ptr;
  struct thread * cur_thread;
  int return_fd;
  lock_acquire(&file_lock);
  cur_thread = thread_current();
  file_ptr = filesys_open(file);
  if (!file_ptr){
    lock_release(&file_lock);
    return -1; //안열리면 exit하는게 아니라 return -1을 해줘야함 
  }
  else {
    // while (cur_thread->fd_bitmap[cur_thread->fd] == 1){
    //   cur_thread->fd += 1; //채워져있으면 1씩 증가
    // }
    // cur_thread->fd_table[cur_thread->fd] = file_ptr;
    // cur_thread->fd_bitmap[cur_thread->fd] = 1;
    // cur_thread->fd += 1;
    // return_fd = cur_thread->fd -1;
    cur_thread->fd_table[cur_thread->fd] = file_ptr;
    cur_thread->fd_bitmap[cur_thread->fd] = 1;
    return_fd = cur_thread->fd;
    // while (cur_thread->fd_bitmap[cur_thread->fd] == 1){
    //   cur_thread->fd += 1; //채워져있으면 1씩 증가
    // }
    while(cur_thread->fd_table[cur_thread->fd]){
       cur_thread->fd += 1;
    }
    lock_release(&file_lock);
    return return_fd;
  }
  lock_release(&file_lock);
  return -1;
}

int filesize(int fd){
  if ((fd>=128) || (fd<0)){
    exit(-1);
  }
  struct thread * cur_thread;
  struct file * cur_fd;
  cur_thread = thread_current();
  cur_fd = cur_thread->fd_table[fd];
  if (!(cur_fd)){
    exit(-1);
  } 
  else {
    return file_length(cur_fd);
  }
}

int read(int fd, void*buffer, unsigned size){
  if ((fd>=128) || (fd<0)){
    exit(-1);
  }
  char ch;
  unsigned read_bytes = 0;
  struct thread * cur_thread;
  struct file * cur_fd;

  lock_acquire(&file_lock);
  if (fd==0){
    for (read_bytes =0 ;read_bytes < size;read_bytes++){
      ch = input_getc();
      if (ch == '\0'){
        break;
      }
      *(char *)buffer = ch;
      buffer++;
      // ((char *)buffer)[read_bytes] = ch;
    }
  }

  else { //fd가 1인것도 들어올까? 이게 말이되냐? 혹시 모르니 생각해놔
    cur_thread =thread_current();
    cur_fd =cur_thread->fd_table[fd];
    if (!(cur_fd)){
      lock_release(&file_lock);
      exit(-1);
    }
    else {
      read_bytes = file_read(cur_fd,buffer,size);
      lock_release(&file_lock);
      return read_bytes;
    }
  }
  lock_release(&file_lock);
  return read_bytes;
}

int write(int fd, const void *buffer, unsigned size){
  if ((fd>=128) || (fd<0)){
    exit(-1);
  }
  struct thread * cur_thread;
  struct file * cur_fd;
  lock_acquire(&file_lock);
  if (fd ==1){
    putbuf(buffer,size);
    lock_release(&file_lock);
    return size;
  }
  else {  //fd가 0인것도 들어올까? 이게 말이되냐? 혹시 모르니 생각해놔
    cur_thread =thread_current();
    cur_fd =cur_thread->fd_table[fd];
    if (!(cur_fd)){
      lock_release(&file_lock);
      exit(-1);
    }
    else{
      int write_bytes = file_write(cur_fd,buffer,size);
      lock_release(&file_lock);
      return write_bytes;
    }
  }
  lock_release(&file_lock);
  return -1;
}



void seek (int fd, unsigned position){
  struct thread * cur_thread;
  struct file * cur_fd;
  cur_thread = thread_current();
  cur_fd =cur_thread->fd_table[fd];
  if (!(cur_fd)){
    exit(-1);
  }
  file_seek(cur_fd, position);
}


unsigned tell(int fd){
  if ((fd>=128) || (fd<0)){
    exit(-1);
  }
  struct thread * cur_thread;
  struct file * cur_fd;
  cur_thread = thread_current();
  cur_fd = cur_thread->fd_table[fd];
  if (!(cur_fd)){
    exit(-1);
  }
  return file_tell(cur_fd);
}

void close(int fd){ //fd 앞을 닫는 경우 뒤에서부터 추가하는게 아니라 앞에 달아줘야할까?? 
  if ((fd>=128) || (fd<0)){
    exit(-1);
  }
  struct file * cur_fd;
  struct thread * cur_thread;
  cur_thread = thread_current();
  cur_fd =cur_thread->fd_table[fd];
  if (!(cur_fd)){
    exit(-1);
  }
  
  cur_thread->fd_bitmap[fd] = 0; //비우기
  file_close(cur_thread->fd_table[fd]);
  cur_thread->fd_table[fd] = NULL;
  for (int i = 2;i<128;i++){
    // if (cur_thread->fd_bitmap[i]==0) {
    //   cur_thread->fd = i;
    //   break;
    // }
    if (cur_thread->fd_table[i]) {
      cur_thread->fd = i;
      break;
    }
  }
  
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
  struct file * cur_fd;

  cur_thread = thread_current();
  for (int i = 2 ; i < 128 ; i++){
    if ((cur_fd = cur_thread->fd_table[i])){
      close(i);
    }
  }
  cur_thread->exit_status = status; //여기서 exit state를 저장을 해줘야함
  thread_exit ();
}



tid_t exec (const char *cmd_line) {
  return process_execute(cmd_line); //여기서 에러체크??
}

int wait (tid_t pid) {
  return process_wait(pid);
}