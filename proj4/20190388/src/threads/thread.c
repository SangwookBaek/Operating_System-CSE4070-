#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b


/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

#ifndef USERPROG
bool thread_prior_aging;
#endif

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static int load_avg; //global var


static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);

static tid_t allocate_tid (void);

static int64_t min_wakeup;
static struct list blocked_list;
extern bool priority_compare(const struct list_elem* , const struct list_elem* , void*);
int thread_get_nice (void);
void thread_set_nice (int new_nice);
int convert_fixed_point(int n);
int convert_to_integer_zero(int x);
int convert_to_integer_nearest(int x);
int add_float_float(int x, int y);
int sub_float_float(int x, int y);
int mul_float_float(int x, int y);
int devide_float_float(int x, int y);
int devide_float_int(int x, int y);
int mul_float_int(int x, int n);
// 여기서부터는 고정 소수점 계산을 위한 함수들
//int x,y : float, int n : integer
#define FRACTION (1<<14)

int convert_fixed_point(int n){
  return n*FRACTION;
}

int convert_to_integer_zero(int x){
  return x/FRACTION;
}

int convert_to_integer_nearest(int x){
  if (x>=0){
    return ((x+FRACTION) / 2)/FRACTION;
  }
  else if (x<=0){
    return ((x-FRACTION) / 2)/FRACTION;
  }
}


int add_float_float(int x, int y){
  return x + y;
}

int sub_float_float(int x, int y){
  return x - y;
}

int mul_float_float(int x, int y){
  int64_t tmp;
  tmp = x;
  tmp = (tmp*y)/FRACTION;
  return (int)tmp;
}

int mul_float_int(int x, int n){
  return x*n;
}

int devide_float_float(int x, int y){
  int64_t tmp;
  tmp = x;
  tmp = (tmp*FRACTION)/y;
  return (int)tmp;
}

int devide_float_int(int x, int n){
  return x/n;
}
// 여기까지


  

void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
  //init blocked list
  initial_thread->nice = 0; //초기화
  initial_thread->recent_cpu = 0;
  load_avg = 0; //초기화
  // thread_started=0;
  list_init(&blocked_list);
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
  // thread_started=1
}


void thread_aging(){
  struct thread* t;
  struct list_elem* e;
  for (e = list_begin(&all_list);e!=list_end(&all_list);e = list_next(e)){
    t = list_entry(e,struct thread, allelem);
    if (t!=idle_thread){
      t->priority = t->priority +1 ;
      if (t->priority >PRI_MAX) {
        t->priority = PRI_MAX;
      }
      else if (t->priority<PRI_MIN){
        t->priority = PRI_MIN;
      }
    }
  }
}




/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t;
  struct list_elem * e;
  int load_avg_tmp;
  int ready_threads_tmp;
  int ready_threads;
  int recent_cpu_tmp;
  int recent_cpu_devider;
  int priority_tmp;
  int nice_tmp;
  /* Update statistics. */
  t = thread_current ();
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();

#ifndef USERPROG
  if (thread_prior_aging ==true){
    thread_aging();
  }
    
  if (thread_mlfqs==true){
    thread_current()->recent_cpu = thread_current()->recent_cpu  + (1<<14);
    if (timer_ticks() % 100 ==0){
      if (!list_empty(&ready_list)){
        for (e=list_begin(&ready_list);e!=list_end(&ready_list);e=list_next(e)){
        ready_threads +=1;
        }
      }
      if (thread_current()!=idle_thread){
        ready_threads +=1;
      }
      load_avg_tmp = devide_float_int((59*(1<<14)),60);
      load_avg_tmp = mul_float_float(load_avg_tmp,load_avg);
      ready_threads_tmp = devide_float_int((1<<14),60);
      ready_threads_tmp = mul_float_float(ready_threads_tmp,ready_threads*(1<<14));
      load_avg = add_float_float(load_avg_tmp,ready_threads_tmp);
      for (e=list_begin(&all_list);e!=list_end(&all_list);e=list_next(e)){
        t = list_entry(e,struct thread, allelem);
        if (t!= idle_thread){
          recent_cpu_tmp = mul_float_int(load_avg,2);
          recent_cpu_tmp = mul_float_float(recent_cpu_tmp,t->recent_cpu);
          recent_cpu_devider = mul_float_int(load_avg,2);
          recent_cpu_devider = recent_cpu_devider + (1<<14);
          recent_cpu_tmp = devide_float_float(recent_cpu_tmp,recent_cpu_devider);
          recent_cpu_tmp = recent_cpu_tmp + (t->nice*(1<<14));
          t->recent_cpu = recent_cpu_tmp;
        }
      }
    }
    if (timer_ticks()%4 ==0){
      for (e=list_begin(&all_list);e!=list_end(&all_list);e=list_next(e)){
        t = list_entry(e,struct thread, allelem);
        if (t!=idle_thread){
          recent_cpu_tmp = t->recent_cpu;
          recent_cpu_tmp = devide_float_int(recent_cpu_tmp,4);
          nice_tmp = (t->nice * 2)*(1<<14);
          priority_tmp = PRI_MAX*(1<<14);
          priority_tmp = sub_float_float(priority_tmp,recent_cpu_tmp);
          priority_tmp = sub_float_float(priority_tmp,nice_tmp);
          priority_tmp = convert_to_integer_zero(priority_tmp);
          if (priority_tmp > PRI_MAX) {
            priority_tmp = PRI_MAX;
          }
          else if (priority_tmp < PRI_MIN){
            priority_tmp = PRI_MIN;
          }
          t->priority = priority_tmp;
        }
      }
    }
  }
#endif
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}


/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  /* Add to run queue. */
  thread_unblock (t);
  #ifndef USERPROG
  if (priority > thread_current ()->priority) {
      thread_yield();
      // thread_try_yield();
  }
  #endif

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;
  // struct thread

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  // list_push_back (&ready_list, &t->elem);
  list_insert_ordered(&ready_list, &t->elem, priority_compare, NULL);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}


bool priority_compare(const struct list_elem* left, const struct list_elem* right , void* aux) {
  struct thread *thread_left = list_entry(left, struct thread, elem);
  struct thread *thread_right = list_entry(right, struct thread, elem);
  if (thread_left->priority > thread_right->priority){
    return true ;
  }
  else {
    return false ;
  }
  // return thread_left->priority > thread_right->priority;
}


/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */


void thread_try_yield(void) {
  if (!list_empty(&ready_list) && thread_current() != idle_thread)
    thread_yield();

}


void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  // if (cur != idle_thread) 
  //   list_push_back (&ready_list, &cur->elem);
  if (cur != idle_thread) 
      list_insert_ordered(&ready_list, &cur->elem, priority_compare, NULL);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

void thread_sleep(int64_t start, int64_t ticks){
    struct thread *t;  
    enum intr_level old_level;  
    old_level = intr_disable();  //일단 intrupt막아
    t = thread_current();   
    // idle 스레드는 sleep 되지 않아야 함   
    ASSERT(t != idle_thread);
    t->sleep_start = start; //추가됨
    t->wakeup = ticks; //ticks전달
    if (min_wakeup  >= ticks){
      min_wakeup = ticks;
    }
    list_push_back(&blocked_list, &t->elem); //blocked list에 집어넣음 
    thread_block(); 
    intr_set_level(old_level);
}

void thread_wakeup(int64_t ticks){
  struct thread *t;
  struct list_elem *e;
  e = list_begin(&blocked_list); 
  while (e != list_end (&blocked_list)){
    t = list_entry (e, struct thread, elem);
    // if ((t->wakeup) <= ticks){
    if ((t->wakeup+t->sleep_start) <= ticks){	// 스레드가 일어날 시간이 되었는지 확인
      e = list_remove (e);	// sleep list 에서 제거
      thread_unblock (t);	// 스레드 unblock
    }
    else{
      e = list_next (e);
    }
  }
}



/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
   int cur_priority;
   struct thread * t;
   struct list_elem * e;
   if (thread_mlfqs != true){
    // cur_priority = thread_current()->priority; //얘가 최대치임
    thread_current()->priority = new_priority; 
    if (!list_empty(&ready_list)){
      // for (e=list_begin(&ready_list);e!=list_end(&ready_list);e=list_next(e)){
      //   t = list_entry(e,struct thread,elem);
      //   if (t->priority > new_priority){
      //     thread_yield();
      //     break;
      //   }
      // }
      e = list_front(&ready_list);
      t = list_entry(e,struct thread, elem);
      if (t->priority > new_priority){
          thread_yield();
          // thread_try_yield();
      }
    }
   }
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) 
{
  int recent_cpu_tmp;
  int priority_tmp;
  int nice_tmp;
  struct thread * t;
  struct list_elem * e ;
  thread_current()->nice = nice;
  recent_cpu_tmp = thread_current()->recent_cpu;
  recent_cpu_tmp = devide_float_int(recent_cpu_tmp,4);
  nice_tmp = (thread_current()->nice * 2)*(1<<14);
  priority_tmp = PRI_MAX*(1<<14);
  priority_tmp = sub_float_float(priority_tmp,recent_cpu_tmp);
  priority_tmp = sub_float_float(priority_tmp,nice_tmp);
  priority_tmp = convert_to_integer_zero(priority_tmp);
  if (priority_tmp > PRI_MAX) {
    priority_tmp = PRI_MAX;
  }
  else if (priority_tmp < PRI_MIN){
    priority_tmp = PRI_MIN;
  }
  thread_current()->priority = priority_tmp;
  if (!list_empty(&ready_list)){
    e = list_front(&ready_list);
    t = list_entry(e,struct thread, elem);
    if (priority_tmp < t->priority){
      thread_yield();
      // thread_try_yield();
      // break;
    }
  }
  /* Not yet implemented. */
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  int tmp;
  tmp=mul_float_int(load_avg,100);
  // return convert_to_integer_nearest(tmp);
  return convert_to_integer_zero(tmp);
  /* Not yet implemented. */
  
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  int tmp;
  tmp = thread_current()->recent_cpu;
  tmp = mul_float_int(tmp,100);
  return convert_to_integer_zero(tmp);
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->magic = THREAD_MAGIC;
  

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);


  #ifdef USERPROG
  t->parent = running_thread();
  t->nice = t->parent->nice; // 부모의 nice를 상속, 부모가 없다면 0을받음 thread_init에서 0을 줬기 때문에
  t->recent_cpu = t->parent->recent_cpu;
  //여기서부터 wait을 위해 추가된 코드
  sema_init(&(t->child_sem),0);
  sema_init(&(t->seg_sem),0);
  sema_init(&(t->oom_sem),0);
  list_init(&(t->child_list));
  
  list_push_back(&(running_thread()->child_list), &(t->child_elem));
  for (int i=2;i<128 ; i++){
    t->fd_table[i] = NULL;
    t->fd_bitmap[i] = 0;
  }
  for (int i=0;i<16 ; i++){
    t->self_fd_table[i] = NULL;
  }
  t->fd = 2;
  t->self_fd = 0;
  t->flag = 0;
  t->fd_bitmap[0] = 1; //check bit
  t->fd_bitmap[1] = 1; //check bit

  // if (priority > t->parent->priority){
  //   thread_yield();
  // }
  #endif


}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
