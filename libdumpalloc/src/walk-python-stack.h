/**
 * walk-python-stack.h
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

#include <stdint.h>

/**
 * This is the signature of the callback function that client code must pass to 
 * the Python stack-walker function.
 */
typedef int (*python_frame_callback_fn)(const char* function, const char* source_file, const uint32_t line_no);

/**
 * This defines the signature of a Python stack-walker function, but we don't 
 * declare the function here, as we want the option of building without 
 * Python support. We will build the stack-walker into a separate shared-object
 * and load it, if available.
 */
typedef void (*walk_python_stack_fn)(python_frame_callback_fn frame_callback);

