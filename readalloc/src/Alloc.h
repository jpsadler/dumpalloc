/**
 * Alloc.h
 *
 * Copyright (c) 2014 John Sadler <deathofathousandpapercuts@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef READALLOC_ALLOC_H
#define READALLOC_ALLOC_H

#include "CallStack.h"
#include "../../libdumpalloc/include/defs.h"

#include <boost/noncopyable.hpp>
#include <stdint.h>

struct Alloc : boost::noncopyable {

	const uint64_t alloc_time;
	const addr_t addr;
	const uint32_t size;

	const CallStack stack;

	Alloc(const uint64_t alloc_time, const addr_t addr, const uint32_t size, CallStack& call_stack) : 
		alloc_time(alloc_time), addr(addr), size(size), stack(call_stack) {
	};
};


#endif // READALLOC_ALLOC_H

