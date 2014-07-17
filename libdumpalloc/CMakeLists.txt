##
# CMakeLists.txt
#
# Copyright (c) 2014 John Sadler <deathofathousandpapercuts@gmail.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
##

cmake_minimum_required ( VERSION 2.6 ) 
project ( DUMPALLOC )

if (CMAKE_CROSSCOMPILING)

set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE=1 -O2 -fvisibility=hidden -ftls-model=initial-exec -fPIC -pthread " )
set( CMAKE_SHARED_LINKER_FLAGS $ENV{LDFLAGS} "-pthread -Wl,-no-as-needed -shared -lrt" )
add_library ( dumpalloc SHARED src/dumpalloc.c )

else()

add_subdirectory ( tests )

endif()


