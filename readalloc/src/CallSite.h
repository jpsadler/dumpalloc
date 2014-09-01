/**
 * CallSite.h
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

#ifndef READALLOC_CALLSITE_H
#define READALLOC_CALLSITE_H


#include "SourceFile.h"
#include "Symbol.h"
#include "../../libdumpalloc/include/defs.h"

#include <boost/noncopyable.hpp>
#include <vector>
#include <stdint.h>

class Symbol;
class CallSite;



struct OnwardCall {

	CallSite* next;
	uint64_t cum_alloc;
	uint64_t times_called;

	explicit OnwardCall(CallSite* next) : next(next), cum_alloc(0U), times_called(0U) {}
};

struct CallSite : boost::noncopyable {

	const addr_t addr;

	const Symbol& from_symbol;
	const SourceFile& source_file;
	const size_t line_no;

	uint64_t times_called;
	uint64_t cum_alloc;

	typedef std::vector<OnwardCall> onward_calls_t;

	onward_calls_t onward_calls;

	CallSite(const addr_t addr, const Symbol& from_symbol, const SourceFile& source_file, const size_t line_no) :
		addr(addr), from_symbol(from_symbol), source_file(source_file), line_no(line_no), times_called(0U),
		cum_alloc(0U) {};

	OnwardCall& add_onward_call(CallSite* const onward_call);

	void clear_costs();
};


#endif // READALLOC_CALLSITE_H

