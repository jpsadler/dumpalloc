/**
 * readalloc.cpp
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

#include "../../libdumpalloc/include/defs.h"
#include "../../libdumpalloc/include/endian.h"

#include <map>
#include <set>
#include <string>
#include <vector>
#include <algorithm>
#include <memory>
#include <boost/noncopyable.hpp>
#include <boost/optional.hpp>
#include <boost/ptr_container/ptr_map.hpp>
#include <boost/ptr_container/ptr_vector.hpp>
#include <boost/foreach.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/unordered_map.hpp>
#include <boost/functional/hash.hpp>
#include <boost/scoped_array.hpp>
#include <boost/lexical_cast.hpp>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <string.h>
#define HAVE_DECL_BASENAME 1
#include <libiberty.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>

#define PACKAGE // to avoid config.h include error in bfd.h
#include <bfd.h>

#include <demangle.h>

static const int read_fd = 0;

static const char* rootfs_dir = 0;
static size_t rootfs_dir_len = 0;

static volatile bool keep_reading = true;

static std::string remote_command;
static std::string remote_program;
static uint32_t remote_pid;

static uint64_t active_alloc_count = 0;
static uint64_t active_alloc_total_cost = 0;


class UniqueString {

	const char* str;
	mutable ssize_t len;

public:

	UniqueString(const char* const str) : str(str), len(-1) {}

	const char* const c_str() const {
		return str;
	}

	const size_t length() const {

		if ( ! str ) {
			return 0;
		}

		if ( len == -1 ) {

			len = strlen(str);
		}	
	}

	bool operator==(const UniqueString& other) {
		return (other.str == str);
	}
};


/**
 * This comparator can be used when we know that there is only one copy of each
 * unique string that we wish to compare (i.e. when we are comparing unique
 * constants).
 * 
 * It avoids the need to compare the characters at all.
 */
struct CmpUniqueStringByAddr {

	bool operator()(const UniqueString& a, const UniqueString& b) const {
		
		return ( a.c_str() < b.c_str() );
	}
};


struct Object;
struct CallSite;
struct SourceFile;

static SourceFile* lookup_or_create_sourcefile(const std::string& name);

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

uint32_t Symbol::next_id = 1;

struct Object : boost::noncopyable {

	const uint32_t id;

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


	explicit Object(const addr_t base_vaddr, const char* const name, const uint32_t name_len) :
		id(next_id++), base_vaddr(base_vaddr), name(name, name_len), abfd(0), syms(0), num_syms(0) {};

	~Object() {

		if (syms) {
			free(syms);
		}

		if (abfd) {
			bfd_close(abfd);
		}
	}

	void init_symtab();

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

	CallSite* lookup_or_create_callsite(const addr_t addr);

	CallSite* add_callsite(const addr_t addr, const Symbol& from_symbol, const SourceFile& source_file,
		const size_t line_no);
};

uint32_t Object::next_id = 1;

struct SourceFile : boost::noncopyable {

	const uint32_t id;
	const std::string name;

	static uint32_t next_id;

	explicit SourceFile(const std::string& name) :
		id(next_id++), name(name) {};
};

uint32_t SourceFile::next_id = 1;

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
};

class CallStack : boost::noncopyable {

	std::vector<CallSite*> _frames;

public:

	typedef typename std::vector<CallSite*>::const_iterator const_iterator;
	typedef const_iterator iterator;	// for BOOST_FOREACH

	size_t size() const {
		return _frames.size();
	}

	const_iterator begin() const {

		return _frames.begin();
	}

	const_iterator end() const {

		return _frames.end();
	}

	void add_frame(CallSite* call_site) {
		_frames.push_back(call_site);
	}

	void swap(CallStack& other) {
		_frames.swap(other._frames);
	}

	explicit CallStack(CallStack& other) {
		_frames.swap(other._frames);
	}

	CallStack() {}

};

struct Alloc : boost::noncopyable {

	const addr_t addr;
	const uint32_t size;

	const CallStack stack;

	Alloc(const addr_t addr, const uint32_t size, CallStack& call_stack) : addr(addr), size(size), stack(call_stack) {
	};
};


struct SymbolLookupInfo {

	Object& object;
	bfd_vma addr;
	bfd_boolean found;
	const char* symbol_name;
	const char* source_file;
	unsigned int line_no;

	explicit SymbolLookupInfo(Object& object, bfd_vma addr) :
		object(object), addr(addr), found(FALSE), symbol_name("??"),
		source_file("??"), line_no(0) {}

	~SymbolLookupInfo() {

	}
};


static void lookup_symbol_in_section(bfd* abfd, asection* section, void *data) {

	//fprintf(stderr, "lookup_symbol_in_section()\n");

	bfd_vma vma;
	bfd_size_type size;
	SymbolLookupInfo* sym_info = (SymbolLookupInfo*)data;

	if (sym_info->found) {
		/* Already found what we're looking for. */
		return;
	}

	if ((bfd_get_section_flags(abfd, section) & SEC_ALLOC) == 0) {
		return;
	}

	vma = bfd_get_section_vma(abfd, section);

	if (sym_info->addr < vma) {
		/* This section starts after our symbol addr, so can't be the one. */
		return;
	}

	size = bfd_get_section_size(section);

	if (sym_info->addr >= vma + size) {
		/* This one ends after our symbol addr, so can't be it either. */
		return;
	}

	/* This section "contains" our symbol addr. But can we find the symbol? */

	sym_info->found = bfd_find_nearest_line(
					abfd, 
					section, 
					sym_info->object.syms,
					sym_info->addr - vma,
					&sym_info->source_file, 
					&sym_info->symbol_name, 
					&sym_info->line_no);
}


CallSite* Object::lookup_or_create_callsite(const addr_t ra) {

	// calculate addr within object.
	addr_t addr = ra-base_vaddr;

	if (base_vaddr == addr_t_max) addr = ra;

	outward_calls_t::iterator i = outward_calls.find(addr);

	if (i != outward_calls.end()) {
		return i->second;
	}

	static UniqueString unknown_symbol_name("??");

	UniqueString symbol_name = unknown_symbol_name;

	const char* source_file_to_use = 0;
	size_t line_no = 0;

	if ( "??" != name ) {

		// not found, we need to lookup the symbol in the bfd now.

		init_symtab();

		SymbolLookupInfo sym_info(*this, (bfd_vma)addr);

		bfd_map_over_sections(abfd, &lookup_symbol_in_section, &sym_info);

		if ( sym_info.found ) {

			symbol_name = UniqueString(sym_info.symbol_name);

		} else {

			fprintf(stderr, "Warning: Failed to lookup symbol. Object: %s, vaddr: 0x%llx\n", name.c_str(), addr);
		}

		// And source file

		source_file_to_use = sym_info.source_file;

		line_no = static_cast<size_t>(sym_info.line_no);
	}

	Symbol* symbol = lookup_symbol(symbol_name);

	if ( ! symbol ) {

		const char* symbol_name_demangled = 0;

		if ( ! (symbol_name == unknown_symbol_name) ) {
			symbol_name_demangled = bfd_demangle(abfd, symbol_name.c_str(), DMGL_ANSI | DMGL_PARAMS);
		}

		symbol = add_symbol(symbol_name, symbol_name_demangled);
	}

	if ( ! source_file_to_use ) {
		source_file_to_use = "??";
	}

	SourceFile* source_file = lookup_or_create_sourcefile(source_file_to_use);

	return add_callsite(addr, *symbol, *source_file, line_no);
}


CallSite* Object::add_callsite(const addr_t addr, const Symbol& from_symbol, const SourceFile& source_file,
	const size_t line_no) {

	CallSite* call_site = new CallSite(addr, from_symbol, source_file, line_no);

	outward_calls.insert(addr, call_site);

	return call_site;
}


void Object::init_symtab() {

	if (abfd) return;

	static const char* target = 0; //"mipsel-linux";

	char abs_object_file[rootfs_dir_len+name.length()+2];

	snprintf(abs_object_file, sizeof(abs_object_file), "%s/%s", rootfs_dir, name.c_str());

	struct stat sb;

	if (stat(abs_object_file, &sb) < 0 || !S_ISREG(sb.st_mode)) {

		fprintf(stderr, "Error: object file: %s doesn't exist or isn't a real file. Can't resolve symbol.\n",
			abs_object_file);

		exit(1);
		return;
	} 

	if ( ! (abfd = bfd_openr(abs_object_file, target))) {

		fprintf(stderr, "Warning: failed to open: %s. Reason: %s.\n", abs_object_file, bfd_errmsg(bfd_get_error()));
		return;
	}

	/* Decompress sections.  */
	abfd->flags |= BFD_DECOMPRESS;

	if (bfd_check_format(abfd, bfd_archive)) {

		fprintf(stderr, "Warning: not an archive: %s\n", abs_object_file);
		return;
	}

	if (! bfd_check_format(abfd, bfd_object)) {

		fprintf(stderr, "Not an object: %s\n", abs_object_file);
	}

	if ((bfd_get_file_flags(abfd) & HAS_SYMS) == 0) {

		fprintf(stderr, "Warning: archive has no symbols: %s\n", abs_object_file);
		return;

	} else {
		
		//fprintf(stderr, "Trying to read symbols...\n");


		long storage;

		bfd_boolean dynamic = FALSE;

		storage = bfd_get_symtab_upper_bound(abfd);

		if (storage == 0) {
		  storage = bfd_get_dynamic_symtab_upper_bound(abfd);
		  dynamic = TRUE;
		}

		if (storage < 0) {
			return;
			//bfd_fatal(bfd_get_filename(sym_info->abfd));
		}

		syms = (asymbol **)xmalloc(storage);

		if (dynamic) {
			num_syms = bfd_canonicalize_dynamic_symtab(abfd, syms);
		} else {
			num_syms = bfd_canonicalize_symtab(abfd, syms);
		}

		/* If there are no symbols left after canonicalization and
		 we have not tried the dynamic symbols then give them a go.  */
		if (num_syms == 0
		  && ! dynamic
		  && (storage = bfd_get_dynamic_symtab_upper_bound(abfd)) > 0) {
			free(syms);
			syms = static_cast<asymbol**>(xmalloc(storage));
			num_syms = bfd_canonicalize_dynamic_symtab(abfd, syms);
		}
	}

	if (num_syms < 0) {

		//fprintf(stderr, "Failed to read syms\n");
		fprintf(stderr, "Warning: failed to read symbol table from: %s\n", abs_object_file);

	}
}


OnwardCall& CallSite::add_onward_call(CallSite* const next_site) {

	BOOST_FOREACH(OnwardCall& o, onward_calls) {

		if (o.next == next_site) {
			return o;
		}
	}

	onward_calls.push_back(OnwardCall(next_site));

	return onward_calls.back();
}

struct CompareObjectPtrByBaseVaddr {

	bool operator()(const Object* const a, const addr_t b) const {

		return (a->base_vaddr < b);
	}
};

class Objects : boost::noncopyable {

	typedef std::vector<Object*> objects_t;
	objects_t objects;

	mutable Object unknown_object;

public:

	typedef typename objects_t::iterator iterator;
	typedef typename objects_t::const_iterator const_iterator;

	Object* lookup_by_ra(const addr_t ra) const {

		const_iterator one_after = lower_bound(objects.begin(), objects.end(), ra, CompareObjectPtrByBaseVaddr());

		if (one_after == objects.end() || one_after == objects.begin()) return &unknown_object;

		Object* object = *(one_after-1);

		return object;
	}

	Object* create(const addr_t base_vaddr, const char* const object_name, const uint32_t object_name_len) {

		Object* object = new Object(base_vaddr, object_name, object_name_len);

		iterator insert_before = lower_bound(objects.begin(), objects.end(), base_vaddr, CompareObjectPtrByBaseVaddr());

		objects.insert(insert_before, object);

		return object;
	}

	// dummy object to account for JIT code and other unresolvable frames.
	Objects() : unknown_object(addr_t_max, "??", 2U) {

		objects.reserve(64U);
	}

	~Objects() {

		BOOST_FOREACH(Object* po, objects) {
			if (po) delete(po);
		}
	}

	iterator begin() {
		return objects.begin();
	}

	iterator end() {
		return objects.end();
	}

	size_t size() const {
		return objects.size();
	}
};

typedef Objects known_objects_t;

static known_objects_t known_objects;



typedef boost::ptr_map<const std::string, SourceFile> source_file_map_t;

static source_file_map_t known_source_files;

static SourceFile* lookup_or_create_sourcefile(const std::string& name) {

	source_file_map_t::iterator i = known_source_files.lower_bound(name);

	if (i != known_source_files.end() && name == i->first) {

		return i->second;

	} else {

		SourceFile* source_file = new SourceFile(name);

		known_source_files.insert(name, source_file);

		return source_file;
	}
}


static void print_stack(const CallStack& stack) {

	BOOST_FOREACH(const CallSite* cs, stack) {

		fprintf(stderr, "0x%llx, %s\n", cs->addr, cs->from_symbol.object.name.c_str());
		fflush(stderr);
	}
}


typedef boost::ptr_map<const addr_t, Alloc> alloc_map_t;

static alloc_map_t known_allocs;

int apply_alloc_cost (Alloc& alloc) { 

	CallSite* prev_callsite = 0;

	BOOST_FOREACH(CallSite* site, alloc.stack) {

		++site->times_called;
		site->cum_alloc += alloc.size;

		if (prev_callsite) {
			OnwardCall& onward_call = site->add_onward_call(prev_callsite);
			++onward_call.times_called;
			onward_call.cum_alloc += alloc.size;
		}

		prev_callsite = site;
	}

	++active_alloc_count;
	active_alloc_total_cost += alloc.size;

	return 0;
}


int remove_alloc_cost (Alloc& alloc) { 

	CallSite* prev_callsite = 0;

	BOOST_FOREACH(CallSite* site, alloc.stack) {

		--site->times_called;
		site->cum_alloc -= alloc.size;

		if (prev_callsite) {
			OnwardCall& onward_call = site->add_onward_call(prev_callsite);
			--onward_call.times_called;
			onward_call.cum_alloc -= alloc.size;
		}

		prev_callsite = site;
	}

	--active_alloc_count;
	active_alloc_total_cost -= alloc.size;

	return 0;
}


static Alloc* add_alloc(const addr_t addr, const uint32_t size, CallStack& stack) {

	std::auto_ptr<Alloc> alloc(new Alloc(addr, size, stack));
	Alloc* raw = alloc.get();


	typename alloc_map_t::iterator existing = known_allocs.find(addr);

	if (existing != known_allocs.end()) {

		fprintf(stderr, "Warning: Duplicate allocation address: 0x%llx detected. Something is very wrong...\n", addr);
		typename alloc_map_t::auto_type old = known_allocs.replace(existing, alloc);

		remove_alloc_cost(*old);

	} else {

		known_allocs.insert(addr, alloc);
	}

	apply_alloc_cost(*raw);

	return raw;
}

static bool delete_alloc(const addr_t addr) {

	alloc_map_t::iterator found_at = known_allocs.find(addr);

	if (found_at != known_allocs.end()) {

		remove_alloc_cost(*found_at->second);

		known_allocs.erase(found_at);

		return true;
	}

	return false;
}


static int read_string(int fd, char* buffer, size_t expected_len) {

	int ret = 0;
	int total_read = 0;

	while (expected_len > 0 && (ret = read(fd, buffer+total_read, expected_len)) > 0) {

		expected_len -= ret;

		total_read += ret;
	}

	return total_read;
}


static int read(int fd, uint32_t& i) {

	int bytes_read = read_string(fd, (char*)&i, sizeof(i));

	if (bytes_read == sizeof(i)) {
		i = le32toh(i);
	}

	return bytes_read;
}

static int read(int fd, int32_t& i) {

	uint32_t u;

	int bytes_read = read_string(fd, (char*)&u, sizeof(u));

	if (bytes_read == sizeof(u)) {
		i = (int32_t)le32toh(u);
	}

	return bytes_read;
}

static int read(int fd, uint64_t& i) {

	int bytes_read = read_string(fd, (char*)&i, sizeof(i));

	if (bytes_read == sizeof(i)) {

		i = le64toh(i);
	}

	return bytes_read;
}


static int read_header() {

	if (read(read_fd, remote_pid) != sizeof(remote_pid)) {
		fprintf(stderr, "Failed to read pid.\n");
		return 1;
	}

	uint32_t command_len = 0;

	if (read(read_fd, command_len) != sizeof(command_len)) {
		return 1;
	}

	remote_command.resize(command_len);

	if (read_string(read_fd, &remote_command[0], command_len) != command_len) {
		return 1;
	}

	size_t space_at = remote_command.find_first_of(" ");
	size_t last_slash_at = remote_command.find_last_of("/", space_at);

	if (last_slash_at == remote_command.npos) last_slash_at = 0;

	remote_program = remote_command.substr(last_slash_at+1, space_at);

	return 0;
}


static int read_object() {

	addr_t base_vaddr;

	//fprintf(stderr, "read_object()\n");

	if (read(read_fd, base_vaddr) != sizeof(base_vaddr)) {
		fprintf(stderr, "Failed to read object base vaddr.\n");
		return 1;
	}

	uint32_t name_len;

	if (read(read_fd, name_len) != sizeof(name_len)) {
		return 1;
	}

	char name[name_len+1];

	if (read_string(read_fd, name, name_len) != name_len) {
		fprintf(stderr, "Failed to read object name. Name len: %lu\n", name_len);
		return 1;
	}

	name[name_len] = 0;

	//fprintf(stderr, "base_vaddr: 0x%llx, name: %s\n", base_vaddr, name);

	known_objects.create(base_vaddr, name, name_len);

	return 0;
}


static int read_alloc() {

	addr_t addr;
	uint32_t size;

	if (read(read_fd, addr) != sizeof(addr) ||
		read(read_fd, size) != sizeof(size)) {

		return 1;
	}

	//fprintf(stderr, "read_alloc() addr: %llx, size: %lu\n", addr, size);

	// read the call stack 

	CallStack stack;

	while ( true ) {

		addr_t ra;

		if (read(read_fd, ra) != sizeof(ra)) {
			fprintf(stderr, "Failed to read frame addr!\n");
			return 1;
		}

		//fprintf(stderr, "frame: 0x%llx\n", ra);

		if (ra == 0) break;


		Object* object = known_objects.lookup_by_ra(ra);

		//fprintf(stderr, "resolved to object: %s\n", object->name.c_str());

		CallSite* call_site = object->lookup_or_create_callsite(ra);

		stack.add_frame(call_site);
	}

	add_alloc(addr, size, stack);

	return 0;
}


static int read_dealloc() {

	addr_t addr;

	if (read(read_fd, addr) != sizeof(addr)) {
		return 1;
	}

	//fprintf(stderr, "read_dealloc() 0x%llx\n", addr);

	if ( ! delete_alloc(addr) ) {
		fprintf(stderr, "Cannot record deletion. Failed to find alloc with addr: 0x%llx\n", addr);
	}

	return 0;
}


typedef int (*read_fn)();

static int start_reading() {

	int32_t rec_type = 0;

	int ret = 0;

	static const read_fn read_fns[] = {
		&read_header,
		&read_alloc,
		&read_dealloc,
		&read_object
	};

	while ( keep_reading ) {

		if ((ret = read(read_fd, rec_type)) != sizeof(rec_type)) {

			if ( ret == -1 ) {
				fprintf(stderr, "Failed to read record type!\n");
			} else if ( ! ret ) {
				fprintf(stderr, "EOF\n");
			}
			
			return 1;
		}

		if (rec_type < 0 || rec_type >= ( sizeof(read_fns)/sizeof(read_fns[0]) ) ) {

			fprintf(stderr, "Error: Unknown record type %d. Looks like stream is corrupt!\n"
				"I'll dump what I have so far...\n", rec_type);

			return 2;
		} 

		if ( read_fns[rec_type]() ) {

			fprintf(stderr, "Record handler failed. %d\n", rec_type);
			return 3;
		}
	}

	if ( ! keep_reading ) {
		
		fprintf(stderr, "Interrupted by signal. I'll dump what I have so far...\n");
	}
}


int generate_callgrind_output (const std::string& file_name) {

	FILE* file = fopen(file_name.c_str(), "w+");

	// Header

	fprintf(file, 
		"version: 1\n"
		"creator: readalloc-0.1\n"
		"pid: %lu\n"
		"cmd: %s\n"
		"part: 1\n\n\n"
		"positions: instr line\n"
		"events: Bytes\n"
		"summary: %llu\n"
		"\n\n",
		remote_pid,
		remote_command.c_str(),
		active_alloc_total_cost
	);

	// All of this is for Callgrind name compression. We can't simply output the numerical 
	// aliases for all the objects, symbols, source files up-front because Kcachegrind gets confused.
	// Instead, we have to output the name along with the id the first time we encounter each
	// entity.

	const size_t total_entities = Object::next_id + Symbol::next_id + SourceFile::next_id;

	boost::scoped_array<int> visited_entities(new int[total_entities]);

	bzero(static_cast<void*>(visited_entities.get()), sizeof(int)*total_entities);

	int* const visited_objects = visited_entities.get();

	int* const visited_symbols = visited_entities.get() + Object::next_id;

	int* const visited_sourcefiles = visited_symbols + Symbol::next_id;


	BOOST_FOREACH(Object* object, known_objects) {

		if ( ! visited_objects[object->id] ) {
			fprintf(file, "ob=(%lu) %s\n", object->id, object->name.c_str());
			visited_objects[object->id] = 1;
		} else {
			fprintf(file, "ob=(%lu)\n", object->id);
		}

		BOOST_FOREACH(const Object::outward_calls_t::value_type& cp, object->outward_calls) {
			
			CallSite* call = cp->second;

			if (call->cum_alloc) {

				if ( ! visited_sourcefiles[call->source_file.id] ) {
					fprintf(file, "fl=(%lu) %s\n", call->source_file.id, call->source_file.name.c_str());
					visited_sourcefiles[call->source_file.id] = 1;
				} else {
					fprintf(file, "fl=(%lu)\n", call->source_file.id);
				}

				if ( ! visited_symbols[call->from_symbol.id] ) {
					fprintf(file, "fn=(%lu) %s\n", call->from_symbol.id, call->from_symbol.get_name());
					visited_symbols[call->from_symbol.id] = 1;
				} else {
					fprintf(file, "fn=(%lu)\n", call->from_symbol.id);
				}

				if (call->onward_calls.empty()) {
	
					// Leaf frame. Doesn't call anything else, so any cost must be 'self' cost.

					fprintf(file, "0x%llx %lu %llu\n\n", call->addr, call->line_no, call->cum_alloc);

				}

				BOOST_FOREACH(OnwardCall& oc, call->onward_calls) {

					CallSite* tc = oc.next;

					if (oc.cum_alloc) {

						if (&tc->from_symbol.object != object) {

							if ( ! visited_objects[tc->from_symbol.object.id] ) {
								fprintf(file, "cob=(%lu) %s\n", tc->from_symbol.object.id,
									tc->from_symbol.object.name.c_str());

								visited_objects[tc->from_symbol.object.id] = 1;
							} else {
								fprintf(file, "cob=(%lu)\n", tc->from_symbol.object.id);
							}
						}

						if (&tc->source_file != &call->source_file) {

							if ( ! visited_sourcefiles[tc->source_file.id] ) {
								fprintf(file, "cfl=(%lu) %s\n", tc->source_file.id, tc->source_file.name.c_str());
								visited_sourcefiles[tc->source_file.id] = 1;

							} else {
								fprintf(file, "cfl=(%lu)\n", tc->source_file.id);
							}
					
						}

						if ( ! visited_symbols[tc->from_symbol.id] ) {
							fprintf(file, "cfn=(%lu) %s\n", tc->from_symbol.id, tc->from_symbol.get_name());
							visited_symbols[tc->from_symbol.id] = 1;
						} else {
							fprintf(file, "cfn=(%lu)\n", tc->from_symbol.id);
						}

						fprintf(file, 
							"calls=%llu 0x%llx %lu\n"
							"0x%llx %lu %llu\n\n",
							oc.times_called, call->addr, call->line_no,
							tc->addr, tc->line_no, oc.cum_alloc
						);

					} // end-if (onward call has cost)

				} // end for-each (onward call)

			} // end-if (call-site has cost)

		} // end for-each (call-site)

	} // end for-each (known object)

	fprintf(file, "totals: %llu\n", active_alloc_total_cost);

	fclose(file);

	return 0;
}


void signal_handler(int sig) {

	keep_reading = false;
}

int init_bfd() {

	// Initialise libbfd for symbol lookup.
	bfd_init();

	fprintf(stderr, "Initialised bfd.\n");

	const char** target_list = bfd_target_list();

	size_t t=0;

	fprintf(stderr, "bfd supported targets: ");

	while (target_list[t]) {
		fprintf(stderr, "%s  ", target_list[t]);
		++t;
	}

	fprintf(stderr, "\n");

	free(target_list);

	return 0;
}

int main(int argc, const char* argv[]) {

	fprintf(stderr,
		"readalloc Copyright (C) 2014 John Sadler\n"
		"This program comes with ABSOLUTELY NO WARRANTY\n"
		"This is free software, and you are welcome to redistribute it\n"
		"under certain conditions; see http://www.gnu.org/licenses/gpl.html for details.\n\n\n");

	if (argc < 2) {
		fprintf(stderr,
			"Usage: cat <libdumpalloc dump> | %s <rootfs dir>\n", argv[0]);
		exit(1);
	}

	rootfs_dir = argv[1];
	rootfs_dir_len = strlen(rootfs_dir);

	fprintf(stderr, "Rootfs: %s\n", rootfs_dir);

	init_bfd();

	signal(SIGTERM, &signal_handler);
	signal(SIGINT, &signal_handler);

	fprintf(stderr, "Entering read loop...\n");

	start_reading();

	fprintf(stderr, "Number of active allocations: %llu, total cost: %llu, number of ELF objects: %lu\n", 
		active_alloc_count, active_alloc_total_cost, known_objects.size());

	std::string callgrind_file;

	if (remote_pid) {
		callgrind_file = remote_program + "." + boost::lexical_cast<std::string>(remote_pid) + ".callgrind";
	} else {
		callgrind_file = "unknown.callgrind";
	}

	fprintf(stderr, "Generating callgrind file: %s\n", callgrind_file.c_str());

	generate_callgrind_output(callgrind_file);

	return 0;
}


