/**
 * CPE/CSC 159 - Operating System Pragmatics
 * California State University, Sacramento
 *
 * Kernel Process Handling
 */

#include <spede/string.h>
#include <spede/stdio.h>
#include <spede/time.h>
#include <spede/machine/proc_reg.h>

#include "kernel.h"
#include "kproc.h"
#include "scheduler.h"
#include "timer.h"

#include "queue.h"

// Process Queues
queue_t run_queue;

// Assuming proc_table is a global array of proc_t
extern proc_t proc_table[PROC_MAX];


/**
 * Scheduler timer callback
 */
void scheduler_timer(void) {
    // Update the active process' run time and CPU time
    if (active_proc != NULL) {
        active_proc->run_time++;
        active_proc->cpu_time++;
    }
}

/**
 * Executes the scheduler
 * Should ensure that `active_proc` is set to a valid process entry
 */
void scheduler_run(void) {
    // Ensure that processes not in the active state aren't still scheduled
    if (active_proc != NULL && active_proc->state != ACTIVE) {
        active_proc = NULL;
    }

    // Check if we have an active process
    if (active_proc != NULL) {

        // Check if the current process has exceeded it's time slice
        if (active_proc->cpu_time >= SCHEDULER_TIMESLICE) {

        // Reset the active time
            active_proc->cpu_time = 0;

            // If the process is not the idle task, add it back to the scheduler
            // Otherwise, simply set the state to IDLE
            if (active_proc->pid != 0) {
                scheduler_add(active_proc);
            } else {
                active_proc->state = IDLE;
            }

            // Unschedule the active process
            active_proc = NULL;
            }  else {
            // Ensure that the process state is set
            active_proc->state = ACTIVE;

        }
    }

    // Check if we have a process scheduled or not
    if (active_proc == NULL) {

    // Get the proces id from the run queue
    int next_pid = queue_init(&run_queue);

    // default to process id 0 (idle task) if a process can't be scheduled
    active_proc = (next_pid != -1) ? &proc_table[next_pid] : &proc_table[0];

        // Update the active proc pointer
        active_proc->state = ACTIVE;
    }


    // Make sure we have a valid process at this point
    if (active_proc == NULL) {
        // Handle the error, log, or take appropriate action
    }

    // Ensure that the process state is set
    active_proc->state = ACTIVE;

}

/**
 * Adds a process to the scheduler
 * @param proc - pointer to the process entry
 */
void scheduler_add(proc_t *proc) {
    // Add the process to the run queue
    queue_in(&run_queue, proc->pid);

    // Set the process state
    proc->state = IDLE;
}

/**
 * Removes a process from the scheduler
 * @param proc - pointer to the process entry
 */
void scheduler_remove(proc_t *proc) {
    // Iterate through each the process queue
   int next_pid;

    if (queue_out(&run_queue, &next_pid) == -1) {
    // Handle the case where the queue is empty
    } else {
        if (next_pid == proc->pid) {
    // If the processis found, skip it; otherwise, ensure that each other process remains in the queue
        }    else {
        // Otherwise, ensure that each other process remains in the queue
        queue_in(&run_queue, next_pid);
    }
    }

    // If the process is the active process, ensure that the active process is cleared so when the
    if (active_proc != NULL && active_proc->pid == proc->pid) {
        active_proc = NULL;
    }
    // scheduler runs again, it will select a new process to run
    proc->state = PROC_TYPE_NONE;
 }

/**
 * Initializes the scheduler, data structures, etc.
 */
void scheduler_init(void) {
    kernel_log_info("Initializing scheduler");

    // Initialize any data structures or variables
    queue_init(&run_queue);

    // Register the timer callback (scheduler_timer) to run every tick
    timer_callback_register(scheduler_timer, SCHEDULER_TIMESLICE, 1);
}

