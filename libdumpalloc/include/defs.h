/**
 * defs.h
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

#ifndef DUMPALLOC_DEFS_H
#define DUMPALLOC_DEFS_H

#include <stdint.h>

static const int32_t record_type_header = 0;
static const int32_t record_type_alloc = 1;
static const int32_t record_type_dealloc = 2;
static const int32_t record_type_object = 3;

typedef uint64_t addr_t;

static const uint64_t addr_t_max = UINT64_MAX;


#endif // DUMPALLOC_DEFS_H


