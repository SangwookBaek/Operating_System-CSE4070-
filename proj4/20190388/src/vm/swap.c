#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "lib/kernel/bitmap.h"

struct lock swap_lock;
struct bitmap *swap_bitmap;
struct block *swap_block;

void swap_init(void)
{
	swap_block = block_get_role(BLOCK_SWAP);
	if(!swap_block)
		return;

	swap_bitmap = bitmap_create(block_size(swap_block) / 8 );
	if(!swap_bitmap)
		return;

	bitmap_set_all(swap_bitmap, 0);

	lock_init(&swap_lock);
}

void swap_in(size_t used_index, void* kaddr)
{
	int i;
	lock_acquire(&swap_lock);
	
	for(i=0; i<8; i++)
	{
		block_read(swap_block, used_index * 8+ i, (uint8_t *)kaddr + i * BLOCK_SECTOR_SIZE);
	}

	bitmap_flip(swap_bitmap, used_index);
	lock_release(&swap_lock);

}

size_t swap_out(void *kaddr)
{
	int i;
	size_t free_index;
	lock_acquire(&swap_lock);

	free_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, 0);
	for(i=0; i<8; i++)
	{
		block_write(swap_block, free_index *8 + i, (uint8_t *)kaddr + i * BLOCK_SECTOR_SIZE);
	}
	lock_release(&swap_lock);
	return free_index;
}

