/**
 * CPE/CSC 159 - Operating System Pragmatics
 * California State University, Sacramento
 *
 * TTY Definitions
 */

#include <spede/string.h>

#include "kernel.h"
#include "timer.h"
#include "tty.h"
#include "vga.h"

// TTY Table
struct tty_t tty_table[TTY_MAX];

// Current Active TTY
struct tty_t *active_tty;

/**
 * Sets the active TTY to the selected TTY number
 * @param tty - TTY number
 */
void tty_select(int n) {

    // Ensure n is within the tty range
    if (n < 0 || n >= TTY_MAX) {
        kernel_panic("Invalid TTY %d", n);
    }

    // Set the active tty to the n table entry 
    active_tty = &tty_table[n];
    kernel_log_info("tty[%d]: selected", n);

    // Indicate that a refresh is needed
    active_tty->refresh = 1;
}

/**
 * Returns the active TTY identifier
 * @return TTY id or -1 on error
 */
int tty_get_active(void) {

    // If there isn't an active tty, return -1
    if (!active_tty) {
        return -1;
    }

    // Return the id of the active tty
    return active_tty->id;
}

/**
 * Refreshes the tty if needed
 */
void tty_refresh(void) {

    // Ensure that a tty is active, otherwise nothing to refresh
    if (!active_tty) {
        kernel_panic("No TTY is selected!");
        return;
    }

    // Set a pointer to the active tty 
    struct tty_t *tty = active_tty;

    // Check if a refresh is needed 
    if (tty->refresh) {
        kernel_log_debug("tty[%d]: refreshing", tty->id);

        int x = 0;
        int y = 0;

        // Remember that x,y is our interpretation of a list of addresses
        // Therefore we need to go through from 0 to TTY_WIDTH * TTY_HEIGHT to cover all addresses
        // This goes through the entire display, character by character, to refresh display
        for (int i = 0; i < TTY_WIDTH * TTY_HEIGHT; i++) {
            // If x position has exceeded the width, return to position 0 and move to next row
            if (x >= VGA_WIDTH) {
                x = 0;  // Return x to 0
                y++;    // Move to next row
            }

            // Use the easy-to-use vga_putc_at to write the character
            // This is writing at x,y coordinates the next i value in our tty buffer. 
            vga_putc_at(x++, y, tty->color_bg, tty->color_fg, tty->buf[tty->pos_scroll*TTY_WIDTH + i]);
        }

        // The screen has been refreshed, so clea the refresh flag
        tty->refresh = 0;
    }
}

/**
 * Updates the active TTY with the given character
 */
void tty_update(char c) {
    if (!active_tty) {
        return;
    }

    struct tty_t *tty = active_tty;

//    kernel_log_debug("tty[%d]: input char=%c", tty->id, c);
//    kernel_log_debug("  before scroll=%d, x=%d, y=%d", tty->pos_scroll, tty->pos_x, tty->pos_y);

    switch (c) {
        case '\t':  // Tab
            tty->pos_x += 4 - tty->pos_x % 4;
            break;

        case '\b':  // Backspace
            if (tty->pos_x != 0) {
                tty->pos_x--;
            } else if (tty->pos_y != 0) {
                tty->pos_y--;
                tty->pos_x = TTY_WIDTH - 1;
            }
            break;

        case '\r': // carriage return
            tty->pos_x = 0;
            break;

        case '\n': // New Line
            tty->pos_y++;
            tty->pos_x = 0;
            break;

        default: // Output a character 
            // pos_scroll is not implemented in this assignment so it will be 0. Otherwise
            // it will act like a y (row) offset and needs to be multiplied by TTY_WIDTH to 
            // get to the correct row. 
            // Second half of formula is as expected... x + y * width
            tty->buf[(tty->pos_scroll * TTY_WIDTH) + (tty->pos_x + tty->pos_y * TTY_WIDTH)] = c;

            // Advance pos_x to the next spot
            tty->pos_x++;
            break;
    }

    // If pos_y exceeds height, need to scroll... This does NOT implement pos_scroll but 
    // still scrolls.
    if (tty->pos_y >= TTY_HEIGHT) {
        int x;
        int y;

        // For each column x...
        for (x = 0; x < TTY_WIDTH; x++) {
            // Go through row by row...
            for (y = 1; y < TTY_HEIGHT; y++) { // Yes, starting at 1 on purpose... 
                // Copy current column/row into previous column/row
                tty->buf[TTY_WIDTH * (y - 1) + x] = tty->buf[TTY_WIDTH * y + x];
            }
        }

        // Clear out last row (keep in mind that y is now at the last row)
        for (x = 0; x < TTY_WIDTH; x++) {
            tty->buf[TTY_WIDTH * (y - 1) + x] = ' ';
        }

        // Set pos_y to the last row
        tty->pos_y = TTY_HEIGHT - 1;
    }

//    kernel_log_debug("  after: scroll=%d, x=%d, y=%d", tty->pos_scroll, tty->pos_x, tty->pos_y);
    tty->refresh = 1;
}

/**
 * Initializes all TTY data structures and memory
 * Selects TTY 0 to be the default
 */
void tty_init(void) {
    kernel_log_info("tty: Initializing TTY driver");

    // void *memset(void *dest, int c, size_t count);
    // Set first count bytes of dest to the value c. Value of c is converted to
    // an unsigned char. Remeber that memset sets the bytes in a block of memory
    // whereas malloc is used to allocate a block of memory. 
    // In this case:
    //  Initializing tty_table to 0
    memset(tty_table, 0, sizeof(tty_table));

    // Now fill in values for tty_table
    for (int i = 0; i < TTY_MAX; i++) {
        tty_table[i].id=i;
        tty_table[i].color_bg = VGA_COLOR_BLACK;
        tty_table[i].color_fg = VGA_COLOR_LIGHT_GREY;
    }

    // Select tty 0 to start with
    tty_select(0);

    // Update the screen on a regular interval (50 times per second right now)
    timer_callback_register(tty_refresh, 2, -1);
}

