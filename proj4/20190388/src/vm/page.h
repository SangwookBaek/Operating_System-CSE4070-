#ifndef VM_PAGE_H
#define VM_PAGE_H
#define VM_BIN 0 						// normal file
#define VM_ANON 1						// swap area


#include <hash.h>
#include <list.h>
#include "threads/thread.h"
#include "threads/vaddr.h"



/* struct for vm_entry */
struct vm_entry{
	uint8_t type;                      // VM_BIN, VM_SWAP
	void *vaddr;                       // virtual address 
	bool writable;                     
	bool is_loaded;                    // if true, physical memory is loaded
	struct file *file;
	size_t offset;
	size_t read_bytes;                   
	size_t zero_bytes;
	size_t swap_slot;
	struct hash_elem elem;             // hash elem for thread's vm
};


/* struct for page */
struct page{
	void *kaddr;
	struct vm_entry *vme;
	struct thread *thread;
	struct list_elem lru;
};

void vm_init(struct hash *vm);
void vm_destroy(struct hash *vm);
struct vm_entry *find_vme(void *vaddr);
bool insert_vme(struct hash *vm, struct vm_entry *vme);
bool delete_vme(struct hash *vm, struct vm_entry *vme);
bool load_file(void *kaddr, struct vm_entry *vme);

#endif
