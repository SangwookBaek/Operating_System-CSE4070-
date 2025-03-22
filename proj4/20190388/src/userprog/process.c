#include "userprog/process.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include <stdlib.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static bool install_page (void *upage, void *kpage, bool writable);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  
  char *fn_copy;
  tid_t tid;
  char tmp_file[128];
  char real_file[128];
  char *token;
  char *token_ptr;
  int token_count=0;

  struct list_elem* e;//추가된 부분
  struct thread* t;
  /* Make a copy of FILE_NAME.ㄹ
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;

  strlcpy (fn_copy, file_name, PGSIZE);


  strlcpy(tmp_file, file_name, sizeof(tmp_file)+1);
  token = strtok_r(tmp_file, " ",&token_ptr);  
  while (token != NULL) {
    if (token_count==0){ //real_file에 따로 저장해보기
      strlcpy(real_file, token, sizeof(real_file)+1);
    }
    break;
  }
  /* Create a new thread to execute FILE_NAME. */
  
  struct thread *cur;
  struct file * cur_fd;
  cur = thread_current();
  lock_acquire(&file_lock);
  if (!filesys_open (real_file)) 
    {
      for (int i = 2 ; i < 128 ; i++){
        cur_fd = cur->fd_table[i];
        if ((cur_fd)){
          file_close(cur_fd);
        }
      }
      lock_release(&file_lock);
      return -1;
    }
  
  tid = thread_create (real_file, PRI_DEFAULT, start_process, fn_copy);
  lock_release(&file_lock);
  sema_down(&thread_current()->oom_sem); //부모는 child가 죽기전에는 절대 죽지마

  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 

  ///이거 일단 넣어놔 추가된 부분
  for (e = list_begin(&thread_current()->child_list); e != list_end(&thread_current()->child_list); e = list_next(e)) {
    t = list_entry(e, struct thread, child_elem);
    if (t->flag == 1) {
      return process_wait(tid);
    }
  }
  ///이부분임
  
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  vm_init(&(thread_current()->vm)); //proj4 에 추가된 코드 현재 thread의 vm 초기화


  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  sema_up(&thread_current()->parent->oom_sem);

  if (!success){
    exit(-1);

    // thread_exit ();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  //for (int i=0;i<1000000000;i++);
  struct list_elem* element;
  
  struct thread* t=NULL;
  int exit_status;
  element = list_begin(&(thread_current()->child_list));
  while (element != list_end(&(thread_current()->child_list))){
    t = list_entry(element, struct thread, child_elem);
    if (child_tid == t->tid){
      sema_down(&(t->child_sem));
      exit_status = t->exit_status;
      list_remove(&(t->child_elem));
      sema_up(&(t->seg_sem));
      return exit_status;
    }
    element = list_next(element);
  }
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur;
  cur = thread_current();
  struct file * cur_fd;
  uint32_t *pd; 

  vm_destroy(&cur->vm); //proj4 에 추가된 내용 vm을 없애놔야함

  // struct file * cur_fd;
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  for (int i = 0;i<16;i++){
    if (cur->self_fd_table[i]){
      file_close(cur->self_fd_table[i]);
    }
  }
  for (int i = 2 ; i < 128 ; i++){
    cur_fd = cur->fd_table[i];
    if ((cur_fd)){
      cur->fd_bitmap[i] = 0;
      file_close(cur_fd);
      // close(i);
      cur->fd_table[i] = NULL;
    }
  }
  sema_up(&(cur->child_sem));
  sema_down(&(cur->seg_sem));
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}


/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */


bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  char tmp_file[128];
  char real_file[128];
  char *token;
  char *token_ptr;
  char *token_arr[24];

  int token_count=0;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
  /* Open executable file. */

  strlcpy(tmp_file, file_name, sizeof(tmp_file)+1);
  token = strtok_r(tmp_file, " ",&token_ptr);  
  while (token != NULL) {
    if (token_count==0){ //real_file에 따로 저장해보기
      strlcpy(real_file, token, sizeof(real_file)+1);
    }
    token_arr[token_count++] = token;
    token = strtok_r(NULL, " ",&token_ptr);
  }
  // for (i=token_count-1;i>=0;i--){
  //   printf("%s\n",token_arr[i]);
  // }

  lock_acquire(&file_lock);
  file = filesys_open (real_file);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", real_file);
      goto done; 
    }
  thread_current()->self_fd_table[thread_current()->self_fd] = file;
  thread_current()->self_fd++;
  file_deny_write(file); //방금 추가된 부분


  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }


  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }
  lock_release(&file_lock);
  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  int for_align=0;
  for (int i=token_count-1;i>=0;i--){ //여기서 하나씩 집어넣어야함
    //printf("%d\n",strlen(token_arr[i]));
    for (int j=strlen(token_arr[i]);j>=0;j--){
      //printf("%c\n",token_arr[i][j]);
      *esp=*esp-1;
      **(char **)esp = token_arr[i][j];
      for_align++;
    }
    token_arr[i] = *esp;
  }
  for_align = 4 - (for_align%4);
  *esp= *esp - (for_align+4) ; //alignment + sentinel
  **(uint32_t **)esp = 0;
  for (int i=token_count-1;i>=0;i--){
    *esp = *esp - 4;
    **(uint32_t **)esp = (uint32_t)token_arr[i];
    if (i==0){
      *esp = *esp - 4;
      **(uint32_t **)esp = (uint32_t)(*esp + 4);
    }
  }

  *esp = *esp - 4;
  **(uint32_t **)esp = token_count;
  *esp = *esp - 4; //return address
  **(uint32_t **)esp = 0;


  // uintptr_t ofs;
  // ofs = (uintptr_t)*esp;
  // int byte_size;
  // byte_size = (int)PHYS_BASE - ofs;
  // hex_dump(ofs, *esp , byte_size ,true);

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done: /* We arrive here whether the load is successful or not. */
  if (lock_held_by_current_thread(&file_lock)){
    lock_release(&file_lock);
  }
  // file_close (file);

  if (!success){
    t->flag = 1;
  }
  return success;
}

/* load() helpers. */

//project 4 stack growth
bool 
expand_stack(void *addr)
{
	struct page *kpage;

	struct vm_entry *vme = malloc(sizeof(struct vm_entry));
	if(!vme){
    return false;
  }
	vme->vaddr     = pg_round_down(addr);
	vme->type      = VM_ANON;
	vme->is_loaded = true;
	vme->writable  = true;
  if (!insert_vme(&thread_current()->vm,vme)){
		return false;
  }

  kpage = alloc_page(PAL_USER);
  // kpage->vme = vme;
  if(!kpage)
	{
		free(vme);
		return false;
	}
  else{
    kpage->vme = vme;
  }
  if(!install_page(vme->vaddr, kpage->kaddr, vme->writable))
	{
		free_page(kpage->kaddr);
		free(vme);
		return false;
	}

  return true;
}


bool verify_stack(void *fault_addr, void*esp){

  void *max = PHYS_BASE - (1<<23);

  if (is_user_vaddr(pg_round_down(fault_addr))&&(fault_addr>= esp-32)&&(fault_addr>=max)){
    return true;
  }
  else {
    return false;
  }
  // return answer;
}



/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  struct vm_entry *vme;
  size_t page_read_bytes;
  size_t page_zero_bytes;
  /* reopen the file for insert re open file to vm_entry */
  struct file *reopen_file = file_reopen(file);
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
	  vme = malloc(sizeof(struct vm_entry));
	  if(!vme){
      return false;
    }
    page_read_bytes =read_bytes;
    if (page_read_bytes > PGSIZE){
      page_read_bytes = PGSIZE;
    }

    page_zero_bytes = PGSIZE - page_read_bytes;

	  vme->file       = reopen_file;
	  vme->offset     = ofs;
	  vme->vaddr      = upage;
	  vme->read_bytes = page_read_bytes;
	  vme->zero_bytes = page_zero_bytes;
	  vme->writable    = writable;
	  vme->is_loaded  = false;
	  vme->type       = VM_BIN;


    insert_vme(&thread_current()->vm, vme);
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    ofs += page_read_bytes;
	  upage += PGSIZE;
  }
  return true;
}

static bool
setup_stack (void **esp) 
{
  struct vm_entry *vme;	
  struct page *kpage;
  bool success = false;
  void *virtual_address = ((uint8_t *) PHYS_BASE) - PGSIZE;
  kpage = alloc_page (PAL_USER | PAL_ZERO);
  if (kpage) 
    {
      success = install_page ( pg_round_down(virtual_address), kpage->kaddr, true);
      if (success){
        vme = malloc(sizeof(struct vm_entry));
        if(!vme){
          free_page(kpage);
          return false;
        }
        *esp = PHYS_BASE;
        vme->vaddr     = pg_round_down(virtual_address);
        vme->is_loaded = true;
        vme->writable  = true;
        vme->type      = VM_ANON;
        kpage->vme     = vme;
        if (insert_vme(&(thread_current()->vm), vme)){
          return true;
        }
        else{
          return false;
        }
      }

      else{
        free_page (kpage->kaddr);
        return false;
      }
    }
  
  return true;
}



/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();
  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}



//proj4 추가 코드
bool 
handle_mm_fault(struct vm_entry *vme)
{
	struct page *kpage;
  kpage = alloc_page(PAL_USER);

	if(!kpage){//page가 할당이 안돼? -> false return
    return false; //없으니까 free 할필요 x??
  } 
		
	if(vme->is_loaded){ //이미 할당되어있으면? page free하고 false 반환
		free_page(kpage);
		return false;
	}
  else {
    kpage->vme = vme; //위 경우 다 아니면 vme를 할당함
  }
  if (vme->type ==VM_BIN){
    if(!load_file(kpage->kaddr,vme)) { //파일 가져와 안돼면 free하고 false반환
				free_page(kpage->kaddr);
				return false;
		}
  }
  else if (vme->type ==VM_ANON){
    swap_in(vme->swap_slot, kpage->kaddr);
  }
  else{ //아니면 안된거?
    return false;
  }

  if(!install_page(vme->vaddr,kpage->kaddr, vme->writable)){ //페이지 넣어주고 null이라면 다시 Free
		free_page(kpage->kaddr);
		return false;
	}
	vme->is_loaded = true; //성공했으면 true반환

  if (vme->is_loaded){
    return true;
  }
}