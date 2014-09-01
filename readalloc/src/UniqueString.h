/**
 * UniqueString.h
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

#ifndef READALLOC_UNIQUESTRING_H
#define READALLOC_UNIQUESTRING_H

#include <sys/types.h>	// for ssize_t
#include <string.h>	// for strlen()

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


#endif // READALLOC_UNIQUESTRING_H


