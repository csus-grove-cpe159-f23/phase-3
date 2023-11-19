/**
 * CPE/CSC 159 - Operating System Pragmatics
 * California State University, Sacramento
 *
 * Kernel Process Handling
 */

#include <spede/stdio.h>
#include <spede/string.h>
#include <spede/machine/proc_reg.h>

#include "kernel.h"
#include "trapframe.h"
#include "kproc.h"
#include "scheduler.h"
#include "timer.h"
#include "queue.h"
#include "vga.h"

// Next available process id to be assigned
int next_pid;

// Process table allocator
queue_t proc_allocator;

// Process table
proc_t proc_table[PROC_MAX];

// Process stacks
unsigned char proc_stack[PROC_MAX][PROC_STACK_SIZE];

/**
 * Looks up a process in the process table via the process id
 * @param pid - process id
 * @return pointer to the process entry, NULL or error or if not found
 */
proc_t *pid_to_proc(int pid) {
    // Iterate through the process table and return a pointer to the valid entry where the process id matches
    // i.e. if proc_table[8].pid == pid, return pointer to proc_table[8]
    // Ensure that the process control block actually refers to a valid process
    return NULL;
}

/**
 * Translates a process pointer to the entry index into the process table
 * @param proc - pointer to a process entry
 * @return the index into the process table, -1 on error
 */
int proc_to_entry(proc_t *proc) {
    // For a given process entry pointer, return the entry/index into the process table
    //  i.e. if proc -> proc_table[3], return 3
    // Ensure that the process control block actually refers to a valid process
    return -1;
}

/**
 * Returns a pointer to the given process entry
 */
proc_t * entry_to_proc(int entry) {
    // For the given entry number, return a pointer to the process table entry
    // Ensure that the process control block actually refers to a valid process
    return NULL;
}

/**
 * Creates a new process
 * @param proc_ptr - address of process to execute
 * @param proc_name - "friendly" process name
 * @param proc_type - process type (kernel or user)
 * @return process id of the created process, -1 on error
 */
int kproc_create(void *proc_ptr, char *proc_name, proc_type_t proc_type) {
    proc_t *proc = NULL;


    // Allocate an entry in the process table via the process allocator

    // Initialize the process control block

    // Initialize the process stack via proc_stack
    // proc->stack = ...

    // Initialize the trapframe pointer at the bottom of the stack
    // proc->trapframe = (trapframe_t *)(&proc->stack[PROC_STACK_SIZE - sizeof(trapframe_t)]);

    // Set each of the process control block structure members to the initial starting values
    // as each new process is created, increment next_pid
    // proc->pid, state, type, run_time, cpu_time, start_time, etc.

    // Copy the passed-in name to the name buffer in the process control block

    // Set the instruction pointer in the trapframe
    proc->trapframe->eip = (unsigned int)proc_ptr;

    // Set INTR flag
    proc->trapframe->eflags = EF_DEFAULT_VALUE | EF_INTR;

    // Set each segment in the trapframe
    proc->trapframe->cs = get_cs();
    proc->trapframe->ds = get_ds();
    proc->trapframe->es = get_es();
    proc->trapframe->fs = get_fs();
    proc->trapframe->gs = get_gs();

    // Add the process to the scheduler

    kernel_log_info("Created process %s (%d) entry=%d", proc->name, proc->pid, -1);

    return -1;
}

/**
 * Destroys a process
 * If the process is currently scheduled it must be unscheduled
 * @param proc - process control block
 * @return 0 on success, -1 on error
 */
int kproc_destroy(proc_t *proc) {
    // Remove the process from the scheduler

    // Clear/Reset all process data (process control block, stack, etc) related to the process

    // Add the process entry/index value back into the process allocator

    return -1;
}

/**
 * Idle Process
 */
void kproc_idle(void) {
    while (1) {
        // Ensure interrupts are enabled
        asm("sti");

        // Halt the CPU
        asm("hlt");
    }
}

/**
 * Test process
 */
void kproc_test(void) {
    // Loop forever
    while (1);
}

/**
 * Initializes all process related data structures
 * Creates the first process (kernel_idle)
 * Registers the callback to display the process table/status
 */
void kproc_init(void) {
    kernel_log_info("Initializing process management");

    // Initialize all data structures and variables
    //   - process table
    //   - process allocator
    //   - process stack

    // Create the idle process (kproc_idle) as a kernel process
}

