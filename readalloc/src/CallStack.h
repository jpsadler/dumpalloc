/**
 * CallStack.h
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

#ifndef READALLOC_CALLSTACK_H
#define READALLOC_CALLSTACK_H

#include <boost/noncopyable.hpp>
#include <vector>


class CallSite;

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

#endif // READALLOC_CALLSTACK_H

