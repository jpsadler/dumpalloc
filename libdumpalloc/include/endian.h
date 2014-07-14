/**
 * endian.h
 *
 * Copyright (c) 2014 John Sadler <deathofathousandpapercuts@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef ENDIAN_H_
#define ENDIAN_H_

# include <byteswap.h>

# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define htole32(x) (x)
#  define le32toh(x) (x)

#  define htole64(x) (x)
#  define le64toh(x) (x)
# else
#  define htole32(x) __bswap_32 (x)
#  define le32toh(x) __bswap_32 (x)
#  define htole64(x) __bswap_64 (x)
#  define le64toh(x) __bswap_64 (x)
# endif

#endif


