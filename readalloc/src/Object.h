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
#include <boost/ptr_container/ptr_set.hpp>
#include <boost/noncopyable.hpp>
#include <boost/foreach.hpp>
#include <boost/function.hpp>

#include <set>

#include <stdint.h>

#define PACKAGE // to avoid config.h include error in bfd.h
#include <bfd.h>

class CallSite;
class SourceFile;


typedef SourceFile* (*sourcefile_lookup_fn)(const std::string&);

class Object : boost::noncopyable {

public:

	const uint32_t id;

	const uint64_t time_added;

	const std::string name;

protected:


	static uint32_t next_id;

	// We keeps a log of the offset addresses of all symbols we fail to resolve.
	// This is so we can dump them out for later analysis.

	typedef std::set<uint64_t> unresolved_symbols_t;
	unresolved_symbols_t unresolved_symbols;

public:

	explicit Object(const uint64_t time_added, const char* const name, const uint32_t name_len) :
		id(next_id++), time_added(time_added), name(name, name_len) {};

	virtual ~Object() {
	}

	virtual CallSite* lookup_or_create_callsite(const addr_t addr, sourcefile_lookup_fn lookup_sourcefile, const std::string& rootfs_dir) = 0;

	void clear_callsite_costs();

	const std::set<uint64_t>& get_unresolved_symbols() const {
		return unresolved_symbols;
	}

	virtual void visit_outward_calls(boost::function<bool (CallSite*)> visitor) = 0;

	static	uint32_t get_next_id() {
		return next_id;
	}
};


class ElfObject : public Object {

	const addr_t base_vaddr;

	typedef boost::ptr_map<const addr_t, CallSite> outward_calls_t;
	outward_calls_t outward_calls;

	typedef boost::ptr_map<const UniqueString, Symbol, CmpUniqueStringByAddr> symbols_t;
	symbols_t symbols;

	// libbfd stuff
	bfd* abfd;
	asymbol** syms;
	long num_syms;

	void init_symtab(const std::string& rootfs_dir);

	Symbol* add_symbol(const UniqueString& name, const char* demangled_name) {

		Symbol* symbol = new NativeSymbol(*this, name, demangled_name);
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


	CallSite* add_callsite(const addr_t addr, const Symbol& from_symbol, const SourceFile& source_file,
		const size_t line_no);


	CallSite* lookup_or_create_callsite(const addr_t addr, sourcefile_lookup_fn lookup_sourcefile, const std::string& rootfs_dir);

	static void lookup_symbol_in_section(bfd* abfd, asection* section, void *data);

	void visit_outward_calls(boost::function<bool (CallSite*)> visitor) {

		BOOST_FOREACH(const outward_calls_t::value_type& cp, outward_calls) {

			CallSite* callsite = cp->second;

			if ( ! visitor(callsite) ) break;
		}
	}

public:

	explicit ElfObject(const uint64_t time_added, const addr_t base_vaddr, const char* const name, const uint32_t name_len) :
		Object(time_added, name, name_len),
		base_vaddr(base_vaddr), abfd(0), syms(0), num_syms(0) {};

	const addr_t get_base_vaddr() const {
		return base_vaddr;
	}

	~ElfObject() {

		if (syms) {
			free(syms);
		}

		if (abfd) {
			bfd_close(abfd);
		}
	}
};


struct ComparePythonCallSite : std::binary_function<const CallSite&, const CallSite&, bool> {

	bool operator()(const CallSite& l, const CallSite& r) const;
};

class PythonObject : public Object {

	typedef boost::ptr_set<CallSite, ComparePythonCallSite> outward_calls_t;
	outward_calls_t outward_calls;

	typedef boost::ptr_map<const std::string, Symbol> symbols_t;
	symbols_t symbols;

	CallSite* lookup_or_create_callsite(const addr_t addr, sourcefile_lookup_fn lookup_sourcefile, const std::string& rootfs_dir) {}

	Symbol* add_symbol(const std::string& name) {
	
		Symbol* symbol = new PythonSymbol(*this, name);
		symbols.insert(name, symbol);
		return symbol;
	}

	Symbol* lookup_symbol(const std::string& name) {

		symbols_t::iterator foundAt = symbols.find(name);

		if (foundAt != symbols.end()) {
			return foundAt->second;
		}

		return 0;
	}

	void visit_outward_calls(boost::function<bool (CallSite*)> visitor) {

		BOOST_FOREACH(CallSite& callsite, outward_calls) {
			if ( ! visitor(&callsite) ) break;
		}
	}


public:

	explicit PythonObject() : Object(0, "<Python>", 8) {}

	CallSite* lookup_or_create_callsite(const char* const function, const char* const source_file, const uint32_t line_no, sourcefile_lookup_fn lookup_sourcefile);
};

#endif // READALLOC_OBJECT_H


