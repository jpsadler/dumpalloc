/**
 * Object.cpp
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

#include "Object.h"
#include "CallSite.h"

#include <boost/foreach.hpp>

#define HAVE_DECL_BASENAME 1
#include <libiberty.h>
#include <demangle.h>

uint32_t Object::next_id = 1;


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



void Object::clear_callsite_costs() {

	BOOST_FOREACH( typename outward_calls_t::reference entry, outward_calls ) {
		entry.second->clear_costs();
	}
}


CallSite* Object::lookup_or_create_callsite(const addr_t ra, sourcefile_lookup_fn lookup_sourcefile, const std::string& rootfs_dir) {

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

		init_symtab(rootfs_dir);

		SymbolLookupInfo sym_info(*this, (bfd_vma)addr);

		bfd_map_over_sections(abfd, &lookup_symbol_in_section, &sym_info);

		if ( sym_info.found ) {

			symbol_name = UniqueString(sym_info.symbol_name);

		} else {
			unresolved_symbols.insert(ra);
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

	SourceFile* source_file = lookup_sourcefile(source_file_to_use);

	return add_callsite(addr, *symbol, *source_file, line_no);
}


CallSite* Object::add_callsite(const addr_t addr, const Symbol& from_symbol, const SourceFile& source_file,
	const size_t line_no) {

	CallSite* call_site = new CallSite(addr, from_symbol, source_file, line_no);

	outward_calls.insert(addr, call_site);

	return call_site;
}


void Object::init_symtab(const std::string& rootfs_dir) {

	if (abfd) return;

	static const char* target = 0; //"mipsel-linux";

	char abs_object_file[rootfs_dir.length()+name.length()+2];

	snprintf(abs_object_file, sizeof(abs_object_file), "%s/%s", rootfs_dir.c_str(), name.c_str());

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


