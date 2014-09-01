/**
 * walk-python-stack.c
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

#include "walk-python-stack.h"
#include <Python.h>
#include <frameobject.h>
#include <stdio.h>
#include <pthread.h>

__attribute__((visibility("default")))
void walk_python_stack(python_frame_callback_fn frame_callback) {

	// I think this one gets the "currently active" thread
	PyThreadState* tstate = PyThreadState_GET();

	long this_thread = pthread_self();

	if (tstate && tstate->thread_id == this_thread && tstate->frame) {

		PyFrameObject* frame;
		for (frame = tstate->frame; frame; frame = frame->f_back) {

			uint32_t line_no = (uint32_t)frame->f_lineno;
			const char* source_file = PyString_AsString(frame->f_code->co_filename);
			const char* function = PyString_AsString(frame->f_code->co_name);

			if ( ! frame_callback(function, source_file, line_no) ) {
				break;
			}
		}
	}
}

