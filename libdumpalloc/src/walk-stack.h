/**
 * walk-stack.h
 *
 * Copyright (c) 2014 John Sadler <deathofathousandpapercuts@gmail.com>
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

#include <stdint.h>

static int get_prev_sp_and_ra(void** prev_sp, void** prev_ra, void* curr_sp, void* curr_ra, const void* scan_end) {

	/*
		Trace backwards until we find the part of the function prologue that
		does the stack adjustment.

		The pointer adjustment will look something like:

			addiu	sp,sp,-40

		The upper 16bits will be: 0x27bd, and the lower 16 bits the (signed)
		offset.

		Whilst working backwards, we also look for loading of the global pointer,
		signifying the start of the function.

		e.g.:

			lui gp,0x5

		We might also hit the end of the previous function with:

			jr ra (0x03e00008)

		If either of these happens, we stop.

		Note: unfortunately, when functions are inlined, we may find multiple
		stack adjustments, although all but the one we're looking for will tend
		to be positive offsets. So we keep on searching.
	*/

	uint32_t* p = curr_ra;

	int32_t sp_offset = 0;

	while (sp_offset >= 0 && p > (uint32_t*)scan_end) {

		if ((unsigned long)p % 4) {
			fprintf(stderr, "**** Oh-oh. Mis-aligned ip: 0x%x looks like we've wandered out of code section.\n", (unsigned long)p);
			return 0;
		}
		--p;

		switch ((*p) & 0xffff0000) {

			case 0x27bd0000: {	// addiu sp, sp
				sp_offset = ( (int32_t)*p << 16 ) >> 16;
				break;
			}

			case 0x3c1c0000: { // lui gp
				// hit start of function?
				return 0;
			}
		
			default: {
				break;
			}
		}

		if ((*p) == 0x03e00008) { // jr ra

			// hit end of prev function?
			return 0;
		}

	}

	if (p <= (uint32_t*)scan_end) {
		return 0;
	}

	*prev_sp = (char*)curr_sp - sp_offset;

	/* 
		Now trace forwards, until we find the part of the function prologue that
		saves the return addr. This will look something like:

			sw	ra,36(sp)

		This relies on the fact that the upper 16bits of the 32-bit instruction
		will always have the same encoding:

			0xafbf

		The lower 16-bits is the (signed) offset (0x0024 in the example above).

		We have to be careful here, since the return address is not actually
		saved on the stack for all functions. So, we stop looking if we hit the
		current pc.

	*/


	do {

		++p;

		if (((*p) & 0xffff0000) == 0xafbf0000) { // sw ra, sp

			int32_t ra_offset = ( (int32_t)*p << 16 ) >> 16;

			*prev_ra = *(void**)((char*)curr_sp + ra_offset);

			return 1;
		}

	} while (p < (uint32_t*)curr_ra);

	return 0;	/* failed to find ra ! */
}

typedef int (*frame_callback_fn)(void*, void*);
typedef const void* (*get_backward_scan_termination_addr_fn_t)(const void*);


static void walk_stack(frame_callback_fn callback, get_backward_scan_termination_addr_fn_t get_scan_end,
	void* user_data) {

	/* grab current ra */
	register void* ra asm("ra");

	/* and stack pointer */
	register void* sp asm("sp");

	void* curr_ra = ra;
	void* curr_sp = (char*)sp;

	/*
		Grab the offset that this function has just added to the stack pointer,
		so we can adjust it back.

		In order to do this, we will start at the current instruction, and trace
		back until we find the stack adjustment (we're self-disassembling).

		MIPS doesn't make the PC available for us to read, so I'm using the
		address of this function as a starting point.
	*/

	uint32_t* p = (uint32_t*)&walk_stack;

	int32_t sp_offset = 0;

	while (((*p) & 0xffff0000) != 0x27bd0000) ++p;

	sp_offset =  ( ((int32_t)*p) << 16 ) >> 16;

	curr_sp -= sp_offset;

	while (curr_ra && callback(curr_ra, user_data) &&
		get_prev_sp_and_ra( &curr_sp, &curr_ra, curr_sp, curr_ra, get_scan_end(curr_ra) )
	) ;
}

#endif // WALK_STACK_H_


