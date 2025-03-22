#ifndef SWAP_H
#define SWAP_H

void swap_init(void);
void swap_in(size_t used_index, void* kaddr);
size_t swap_out(void* kaddr);
#endif

// #ifndef SWAP_H
// #define SWAP_H

// void swap_init(void);
// void swap_in(size_t used_index, void* kaddr);
// size_t swap_out(void* kaddr);

// #endif