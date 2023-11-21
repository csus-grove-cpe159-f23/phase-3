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
    for (unsigned int i = 0; i < PROC_MAX; i++) {
        if (proc_table[i].pid == pid) {
            return &proc_table[i];
        }
    }

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
    if (proc == NULL) {
        return -1;
    }

    for (unsigned int i = 0; i < PROC_MAX; i++) {
        if (proc->pid == proc_table[i].pid) {
            return i;
        }
    }

    return -1;
}

/**
 * Returns a pointer to the given process entry
 */
proc_t * entry_to_proc(int entry) {
    // For the given entry number, return a pointer to the process table entry
    // Ensure that the process control block actually refers to a valid process
    if (entry >= 0 && entry < PROC_MAX) {
        return &proc_table[entry];
    }

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
   
    if (proc_name == NULL) {
        kernel_panic("Invalid process title\n");
    }

    if (proc_ptr == NULL) {
        kernel_panic("Invalid function pointer");
    }

    if (queue_out(&proc_allocator, &proc_entry) != 0) {
        kernel_log_warn("Unable to allocate a process entry");
        return -1;
    }

    // Allocate the process table entry
    proc = &proc_table[proc_entry];

    // Initialize the PCB entry for the process
    memset(proc, 0, sizeof(proc_t));

    // Initialize the process stack via proc_stack
    proc->stack = proc_stack[proc_entry];

    // Initialize the trapframe pointer at the bottom of the stack
    proc->trapframe = (trapframe_t *)(&proc->stack[PROC_STACK_SIZE - sizeof(trapframe_t)]);

    // Set each of the process control block structure members to the initial starting values
    // as each new process is created, increment next_pid
    // proc->pid, state, type, run_time, cpu_time, start_time, etc.
    proc->pid         = next_pid++;
    proc->state       = IDLE;
    proc->type        = proc_type;
    proc->run_time    = 0;
    proc->cpu_time    = 0;
    proc->start_time  = timer_get_ticks();


    // Copy the passed-in name to the name buffer in the process control block
    strncpy(proc->name, proc_name, PROC_NAME_LEN);

    // Ensure the stack for the process is cleared
    memset(proc->stack, 0, PROC_STACK_SIZE);

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
    scheduler_add(proc);

    kernel_log_info("Created process %s (%d) entry=%d", proc->name, proc->pid, -1);

    return proc->pid;
}

/**
 * Destroys a process
 * If the process is currently scheduled it must be unscheduled
 * @param proc - process control block
 * @return 0 on success, -1 on error
 */
int kproc_destroy(proc_t *proc) {
    if (proc == NULL) {
        kernel_panic("Invalid process!");
        return -1;
    }

    if (proc->pid == 0) {
        kernel_log_error("Cannot exit the idle task");
        return -1;
    }

    // Remove the process from the scheduler
    scheduler_remove(proc);

    // Clean up the process table for the process
    int entry = proc_to_entry(proc);
    if (entry < 0) {
        kernel_panic("Error obtaining the process table entry");
    }

    kernel_log_info("Destroying process %s (%d) entry=%d", proc->name, proc->pid, entry);

    // Reset the process stack
    memset(proc->stack, 0, PROC_STACK_SIZE);

    // Reset the process control block
    memset(proc, 0, sizeof(proc_t));

    // Add the entry back to the process queue (to be recycled)
    if (queue_in(&proc_allocator, entry) != 0) {
        kernel_log_warn("Unable to queue entry back into allocator");
    }

    return 0;
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
 * Attaches a process to a TTY
 * Points the input / output buffers to the TTY's input/output buffers
 *   IO[0] should be input
 *   IO[1] should be output
 */
int kproc_attach_tty(int pid, int tty_number) {
    proc_t *proc = pid_to_proc(pid);
    struct tty_t *tty = tty_get(tty_number);

    if (proc && tty) {
        kernel_log_debug("Attaching PID %d to TTY id %d", proc->pid, tty_number);
        proc->io[PROC_IO_IN] = &tty->io_input;
        proc->io[PROC_IO_OUT] = &tty->io_output;
        return 0;
    }

    return -1;
}

/**
 * Initializes all process related data structures
 * Creates the first process (kernel_idle)
 * Registers the callback to display the process table/status
 */
void kproc_init(void) {
    int pid;

    kernel_log_info("Initializing process management");

    // Initialize the process queue
    queue_init(&proc_allocator);

    // Populate the process queue
    for (int i = 0; i < PROC_MAX; i++) {
        queue_in(&proc_allocator, i);
    }

    // Initialize the process table
    memset(&proc_table, 0, sizeof(proc_table));

    // Initialize the process stacks
    memset(proc_stack, 0, sizeof(proc_stack));

    // Create/execute the idle process (kproc_idle)
    pid = kproc_create(kproc_idle, "idle", PROC_TYPE_KERNEL);

    kernel_log_info("Created idle process %d", pid);

    for (int i = 1; i < 5; i++) {
        pid = kproc_create(prog_shell, "shell", PROC_TYPE_USER);

        kernel_log_debug("Created shell process %d", pid);

        // Attach the process to the TTY
        kproc_attach_tty(pid, i);
    }

    for (int i = 0; i < 3; i++) {
        pid = kproc_create(prog_ping, "ping", PROC_TYPE_USER);
        kernel_log_debug("Created ping process %d", pid);

        kproc_attach_tty(pid, (TTY_MAX - (pid % 2) - 1));
    }

    for (int i = 0; i < 3; i++) {
        pid = kproc_create(prog_pong, "pong", PROC_TYPE_USER);
        kernel_log_debug("Created pong process %d", pid);

        kproc_attach_tty(pid, (TTY_MAX - (pid % 2) - 1));
    }
}

