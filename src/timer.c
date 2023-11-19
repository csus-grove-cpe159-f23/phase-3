/**
 * CPE/CSC 159 - Operating System Pragmatics
 * California State University, Sacramento
 *
 * Timer Implementation
 */
#include <spede/string.h>

#include "interrupts.h"
#include "kernel.h"
#include "queue.h"
#include "timer.h"

/**
 * Data structures
 */
// Timer data structure
typedef struct timer_t {
    void (*callback)(); // Function to call when the interval occurs
    int interval;       // Interval in which the timer will be called
    int repeat;         // Indicate how many intervals to repeat (-1 should repeat forever)
} timer_t;

/**
 * Variables
 */

// Number of timer ticks that have occured
int timer_ticks;

// Timers table; each item in the array is a timer_t struct
timer_t timers[TIMERS_MAX];

// Timer allocator; used to allocate indexes into the timers table
queue_t timer_allocator; // Struct contains head, tail, size, items[]


/**
 * Registers a new callback to be called at the specified interval
 * @param func_ptr - function pointer to be called
 * @param interval - number of ticks before the callback is performed
 * @param repeat   - Indicate how many intervals to repeat (-1 should repeat forever)
 *
 * @return the allocated timer id or -1 for errors
 */
int timer_callback_register(void (*func_ptr)(), int interval, int repeat) {
    int timer_id = -1;
    timer_t *timer;

    // Ensure a pointer was passed... You never know with programmers. 
    if (!func_ptr) {
        kernel_log_error("timer: invalid function pointer");
        return -1;
    }

    // Obtain a timer id from queue
    if (queue_out(&timer_allocator, &timer_id) != 0) {
        kernel_log_error("timer: unable to allocate a timer");
        return -1;
    }

    // set local timer var to a timer at timer_id position
    timer = &timers[timer_id];
    
    // Now save func_ptr to callback var along with interval and repeat
    timer->callback = func_ptr;
    timer->interval = interval;
    timer->repeat = repeat;

    // Return timer_id to the calling function
    return timer_id;
}

/**
 * Unregisters the specified callback
 * @param id
 *
 * @return 0 on success, -1 on error
 */
int timer_callback_unregister(int id) {
    timer_t *timer;

    if (id < 0 || id >= TIMERS_MAX) {
        kernel_log_error("timer: callback id out of range: %d", id);
        return -1;
    }

    // Set local timer pointer to address of the timer being unregistered 
    timer = &timers[id];
    // Clear out memory for the timer 
    memset(timer, 0, sizeof(timer_t));

    // Clear up space in the queue
    if (queue_in(&timer_allocator, id) != 0) {
        kernel_log_error("timer: unable to queue timer entry back to allocator");
        return -1;
    }

    return 0;
}

/**
 * Returns the number of ticks that have occured since startup
 *
 * @return timer_ticks
 */
int timer_get_ticks() {
    return timer_ticks;
}

/**
 * Timer IRQ Handler
 *
 * Should perform the following:
 *   - Increment the timer ticks every time the timer occurs
 *   - Handle each registered timer
 *     - If the interval is hit, run the callback function
 *     - Handle timer repeats
 */
void timer_irq_handler(void) {
    timer_t *timer;

    // Increment the timer_ticks value
    timer_ticks++;

    // Iterate through the timers table
    for (int i = 0; i < TIMERS_MAX; i++) {
        // Load up first timer into local var 
        timer = &timers[i];

        // If we have a valid callback, check if it needs to be called
        if (timer->callback) {
            // If the timer interval is hit, run the callback function
            if (timer_ticks % timer->interval == 0) {
                timer->callback();
            }

            // If the timer repeat is greater than 0, decrement
            if (timer->repeat > 0) {
                timer->repeat--;
            } else if (timer->repeat == 0) {
                // If the timer repeat is equal to 0, unregister the timer
                timer_callback_unregister(i);
            }
        }
    }
}

/**
 * Initializes timer related data structures and variables
 */
void timer_init(void) {
    kernel_log_info("Initializing timer");

    // Set the initial system time
    timer_ticks = 0;

    // Initialize the timers data structures
    memset(timers, 0, sizeof(timers));

    // Initialize the timer callback allocator queue
    queue_init(&timer_allocator);

    // Populate items into the allocator queue
    // Or, another way of looking at it, populating queue with the max
    // number of timers we want to allow in our OS. 
    for (int i = 0; i < TIMERS_MAX; i++) {
        if (queue_in(&timer_allocator, i) != 0) {
            kernel_log_warn("timer: unable to queue timer allocator %d", i);
        }
    }

    // Register the Timer IRQ
    // Note: isr_entry_timer is from interrupts.h and timer_irq_handler 
    // is our function above.
    interrupts_irq_register(IRQ_TIMER, isr_entry_timer, timer_irq_handler);
}

