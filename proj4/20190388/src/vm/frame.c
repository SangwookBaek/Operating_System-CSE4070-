#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "lib/kernel/list.h"
#include "userprog/syscall.h"
#include <threads/malloc.h>
#include <stdio.h>

void lru_list_init(void){
	list_init(&lru_list);
	lock_init(&lru_list_lock);
	lru_clock = NULL;
}

void add_page_to_lru_list(struct page *page) {
	if(page){
		list_push_back(&lru_list, &page->lru); //맨뒤에 넣기
	}
}


void del_page_from_lru_list(struct page* page) {
	struct list_elem * e;
	if(page){
		e = list_remove(&page->lru);
		if(lru_clock == page){
			lru_clock = list_entry(e, struct page, lru);
		}
	}
}

struct page *alloc_page(enum palloc_flags flags) {
	if(!(flags & PAL_USER))
		return NULL;
	uint8_t *kpage;
	struct page *new_page;
	kpage= palloc_get_page(flags); //새로 할당
	/* if fail, free physical memory and retry physical memory allocate*/
	while(!kpage){ //null이야?
		try_to_free_pages();
		kpage = palloc_get_page(flags);
	}
	new_page = malloc(sizeof(struct page));
	new_page->thread = thread_current();
	if(!new_page){ //없으면 free해라
		palloc_free_page(kpage);
		return NULL;
	}
	new_page->kaddr  = kpage; //초기화
	/* insert page to lru list */
	lock_acquire(&lru_list_lock);
	add_page_to_lru_list(new_page);
	lock_release(&lru_list_lock);
	return new_page;
}

void free_page(void *kaddr) {
	struct list_elem *e;
	struct page *lru_page=NULL;
	lock_acquire(&lru_list_lock);
	for(e = list_begin(&lru_list); e != list_end(&lru_list); e = list_next(e)){
		lru_page = list_entry(e, struct page, lru);
		if(lru_page->kaddr == kaddr){ //발견했으며면
			break;
		}
	}
	if (lru_page){
		__free_page(lru_page);
	}
	lock_release(&lru_list_lock);
}

void __free_page(struct page *page) {
	del_page_from_lru_list(page);
	pagedir_clear_page(page->thread->pagedir, pg_round_down(page->vme->vaddr));
	palloc_free_page(page->kaddr);

	free(page); //메모리 해제까지 해야함
}

struct list_elem* 
get_next_lru_clock(void) {
	struct list_elem *e;

	if(list_empty(&lru_list))
		return NULL;

	if(lru_clock == list_end(&lru_list) || !lru_clock)
	{
		return list_begin(&lru_list);
	}
	if (list_next(lru_clock) == list_end(&lru_list)){
		return list_begin(lru_clock);
	}
	else {
		return list_next(&lru_list);
	}

	return lru_clock;
}

void 
try_to_free_pages(void)
{
	struct thread *t;
	struct list_elem *e;
	struct page *lru_page;
	lock_acquire(&lru_list_lock);
	if(list_empty(&lru_list) == true){
		lock_release(&lru_list_lock);
		return;
	}
	while(true){
		e = get_next_lru_clock();
		if(!e){
			break;
		}
		lru_page = list_entry(e, struct page, lru);
		
		t = lru_page->thread;
		if(pagedir_is_accessed(t->pagedir, lru_page->vme->vaddr)){
			pagedir_set_accessed(t->pagedir, lru_page->vme->vaddr, false);
			continue;
		}
		if(pagedir_is_dirty(t->pagedir, lru_page->vme->vaddr) || lru_page->vme->type == VM_ANON){
			
			lru_page->vme->type = VM_ANON;
			lru_page->vme->swap_slot = swap_out(lru_page->kaddr); 			
		}
		
		lru_page->vme->is_loaded = false;
		pagedir_clear_page(t->pagedir, lru_page->vme->vaddr);
		__free_page(lru_page);
		break;
	}
    lock_release(&lru_list_lock);
	return;
}
