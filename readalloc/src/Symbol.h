/**
 * Symbol.h
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

#ifndef READALLOC_SYMBOL_H
#define READALLOC_SYMBOL_H

#include "UniqueString.h"

#include <boost/noncopyable.hpp>
#include <stdint.h>
#include <stdlib.h>

class Object;

struct Symbol : boost::noncopyable {

	const uint32_t id;

	const Object& object;
	const UniqueString name;
	const char* demangled_name;

	const uint64_t cum_alloc;

	static uint32_t next_id;

	Symbol(const Object& object, const UniqueString& name, const char* demangled_name) :
		id(next_id++), object(object), name(name), demangled_name(demangled_name), cum_alloc(0U) {}

	~Symbol() {
		if (demangled_name) {
			free(const_cast<char*>(demangled_name));
		}
	}

	const char* get_name() const {

		return (demangled_name?demangled_name:name.c_str());
	}
};

#endif // READALLOC_SYMBOL_H

