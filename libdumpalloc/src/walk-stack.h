/**
 * walk-stack.h
 *
 * Copyright (c) 2015 John Sadler <deathofathousandpapercuts@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */


#ifndef WALK_STACK_H_
#define WALK_STACK_H_

typedef int (*frame_callback_fn)(void*, void*);
typedef const void* (*get_backward_scan_termination_addr_fn_t)(const void*);


static void walk_stack(frame_callback_fn callback, get_backward_scan_termination_addr_fn_t get_scan_end,
	void* user_data) __attribute__((noinline));


#ifdef __mips__

#include "walk-stack-mipsel32.h"
const static int have_walk_stack = 1;

#else

const static int have_walk_stack = 0;

static void walk_stack(frame_callback_fn callback, get_backward_scan_termination_addr_fn_t get_scan_end,
	void* user_data) {
	// dummy
}

#endif


#endif // WALK_STACK_H_

