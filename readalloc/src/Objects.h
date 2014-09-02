/**
 * Objects.h
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

#ifndef READALLOC_OBJECTS_H
#define READALLOC_OBJECTS_H

#include "Object.h"
#include "../../libdumpalloc/include/defs.h"

#include <boost/foreach.hpp>
#include <vector>

struct CompareObjectPtrByBaseVaddr {

	bool operator()(const ElfObject* const a, const addr_t b) const {

		return (a->get_base_vaddr() < b);
	}
};

class Objects : boost::noncopyable {

	typedef std::vector<Object*> objects_t;
	objects_t objects;

	typedef std::vector<ElfObject*> elf_objects_t;
	elf_objects_t elf_objects;

	mutable ElfObject unknown_object;
	mutable PythonObject python_object;

public:

	typedef typename objects_t::iterator iterator;
	typedef typename objects_t::const_iterator const_iterator;

	typedef typename elf_objects_t::iterator elf_iterator;
	typedef typename elf_objects_t::const_iterator elf_const_iterator;

	PythonObject& get_python_object() const {
		return python_object;
	}

	Object* lookup_by_ra(const addr_t ra) const {

		elf_const_iterator one_after = lower_bound(elf_objects.begin(), elf_objects.end(), ra, CompareObjectPtrByBaseVaddr());

		if (one_after == elf_objects.end() || one_after == elf_objects.begin()) return &unknown_object;

		Object* object = *(one_after-1);

		return object;
	}

	Object* create(const uint64_t time_added, const addr_t base_vaddr, const char* const object_name, const uint32_t object_name_len) {

		ElfObject* object = new ElfObject(time_added, base_vaddr, object_name, object_name_len);

		elf_iterator insert_before = lower_bound(elf_objects.begin(), elf_objects.end(), base_vaddr, CompareObjectPtrByBaseVaddr());

		elf_objects.insert(insert_before, object);

		objects.push_back(object);

		return object;
	}

	// dummy object to account for JIT code and other unresolvable frames.
	Objects() :
		unknown_object(0, addr_t_max, "??", 2U) {

		objects.reserve(64U);

		objects.push_back(&python_object);

		elf_objects.reserve(objects.size());
	}

	~Objects() {

		BOOST_FOREACH(ElfObject* po, elf_objects) {
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


#endif // READALLOC_OBJECTS_H

