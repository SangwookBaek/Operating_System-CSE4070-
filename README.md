
# Operating Systems Projects (CSE4070)

This repository contains implementations of **five projects (proj0 to proj4)** for the Operating Systems course (CSE4070).  
All projects are based on the [Pintos OS](https://web.stanford.edu/class/cs140/projects/pintos/pintos_1.html), and are tested using the CSPRO server environment.

---

## 📁 Project Overview

### 🔧 Project 0: Environment Setup & Pintos Data Structures
- Install and configure **Pintos** on CSPRO servers (cspro9 / cspro10).
- Practice using **Linux commands** and **Vim**.
- Study and test Pintos kernel **data structures**:
  - Doubly linked lists (`list`)
  - Hash tables (`hash`)
  - Bitmaps (`bitmap`)
- Understand and use Pintos-specific APIs like `list_entry`, `hash_entry`, `bitmap_count`, etc.

---

### 👤 Project 1: User Program (Part 1)
- Implement essential components to **run user programs** in Pintos.
- Key tasks:
  - Argument parsing & user stack setup
  - **System call handler** for:
    - `halt`, `exit`, `exec`, `wait`, `read`, `write`
  - Implement **user memory access checks**
  - Add **two new system calls**:
    - `fibonacci(int n)`
    - `max_of_four_int(int a, int b, int c, int d)`

---

### 📁 Project 2: File System System Calls
- Extend Pintos to support **file system-related system calls**:
  - `create`, `remove`, `open`, `close`, `filesize`, `read`, `write`, `seek`, `tell`
- Understand Pintos **base file system** and manage **file descriptors per thread**.
- Deny write access to executable files.
- Use **synchronization** (locks/semaphores) to protect critical sections in file access.

---

### 🧵 Project 3: Threads & Scheduling
- Modify Pintos kernel to support more advanced scheduling:
  - **Alarm Clock**: block/wake threads using `timer_sleep`
  - **Priority Scheduler**:
    - Support for thread priorities (0–63)
    - **Priority aging** to prevent starvation
  - **Advanced Scheduler (Bonus)**:
    - BSD Scheduler (MLFQ)
    - Implement `load_avg`, `recent_cpu`, `nice` value tracking
    - Use fixed-point arithmetic

---

### 🧠 Project 4: Virtual Memory
- Introduce **virtual memory management** to Pintos:
  - Handle **page faults** using `page_fault()` in `exception.c`
  - Implement **Supplemental Page Table (SPT)**
  - **Stack growth** on-demand
  - Support **page swapping** using a swap disk:
    - `swap-in`, `swap-out`
    - `block_read`, `block_write`
  - Implement **pseudo-LRU (second chance)** page replacement

---

## 🛠 Technologies Used

- **Language**: C (with limited libc)
- **Platform**: Pintos on QEMU (x86), CSPRO Linux servers
- **Tools**: GDB, make, fixed-point arithmetic, synchronization primitives
- **Concepts Covered**:
  - Process/thread management
  - System calls & interrupt handling
  - Scheduling & synchronization
  - File system interaction
  - Virtual memory & paging

---
