/**
 * Object.h
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

#ifndef READALLOC_OBJECT_H
#define READALLOC_OBJECT_H

#include "UniqueString.h"
#include "Symbol.h"
#include "../../libdumpalloc/include/defs.h"

#include <boost/ptr_container/ptr_map.hpp>
#include <boost/noncopyable.hpp>

#include <set>

#include <stdint.h>

#define PACKAGE // to avoid config.h include error in bfd.h
#include <bfd.h>

class CallSite;
class SourceFile;


typedef SourceFile* (*sourcefile_lookup_fn)(const std::string&);

struct Object : boost::noncopyable {

	const uint32_t id;

	const uint64_t time_added;

	const addr_t base_vaddr;

	const std::string name;

	typedef boost::ptr_map<const UniqueString, Symbol, CmpUniqueStringByAddr> symbols_t;
	symbols_t symbols;

	typedef boost::ptr_map<const addr_t, CallSite> outward_calls_t;
	outward_calls_t outward_calls;

	// libbfd stuff
	bfd* abfd;
	asymbol** syms;
	long num_syms;

	static uint32_t next_id;

	// We keeps a log of the offset addresses of all symbols we fail to resolve.
	// This is so we can dump them out for later analysis.
	typedef std::set<uint64_t> unresolved_symbols_t;
	unresolved_symbols_t unresolved_symbols;

	explicit Object(const uint64_t time_added, const addr_t base_vaddr, const char* const name, const uint32_t name_len) :
		id(next_id++), time_added(time_added), base_vaddr(base_vaddr), name(name, name_len), abfd(0), syms(0), num_syms(0) {};

	~Object() {

		if (syms) {
			free(syms);
		}

		if (abfd) {
			bfd_close(abfd);
		}
	}

	void init_symtab(const std::string& rootfs_dir);

	Symbol* add_symbol(const UniqueString& name, const char* demangled_name) {
	
		Symbol* symbol = new Symbol(*this, name, demangled_name);
		symbols.insert(name, symbol);
		return symbol;
	}

	Symbol* lookup_symbol(const UniqueString& name) {

		symbols_t::iterator foundAt = symbols.find(name);

		if (foundAt != symbols.end()) {
			return foundAt->second;
		}

		return 0;
	}

	CallSite* lookup_or_create_callsite(const addr_t addr, sourcefile_lookup_fn lookup_sourcefile, const std::string& rootfs_dir);

	CallSite* add_callsite(const addr_t addr, const Symbol& from_symbol, const SourceFile& source_file,
		const size_t line_no);

	void clear_callsite_costs();
};

#endif // READALLOC_OBJECT_H


