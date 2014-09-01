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

	Object* create(const uint64_t time_added, const addr_t base_vaddr, const char* const object_name, const uint32_t object_name_len) {

		Object* object = new Object(time_added, base_vaddr, object_name, object_name_len);

		iterator insert_before = lower_bound(objects.begin(), objects.end(), base_vaddr, CompareObjectPtrByBaseVaddr());

		objects.insert(insert_before, object);

		return object;
	}

	// dummy object to account for JIT code and other unresolvable frames.
	Objects() : unknown_object(0, addr_t_max, "??", 2U) {

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


#endif // READALLOC_OBJECTS_H

