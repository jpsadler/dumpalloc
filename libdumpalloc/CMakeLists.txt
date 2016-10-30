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

find_package(PythonLibs)

set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE=1 -O3 -fno-reorder-blocks -fvisibility=hidden -ftls-model=initial-exec -fPIC -pthread -fasynchronous-unwind-tables" )

set( CMAKE_SHARED_LINKER_FLAGS $ENV{LDFLAGS} "-pthread -Wl,-no-as-needed -shared -lrt -ldl" )
add_library ( dumpalloc SHARED src/dumpalloc.c )

# Only build the Python support if Python libs are available. It's a relatively-heavy
# depenency, so we won't build it ourselves.
#
if (PYTHON_LIBRARIES)
add_library ( dumpalloc-python SHARED src/walk-python-stack.c )
target_link_libraries ( dumpalloc-python "${PYTHON_LIBRARIES}" )
target_include_directories ( dumpalloc-python PRIVATE "${PYTHON_INCLUDE_DIRS}" )
endif()

#add_subdirectory ( manual-test-programs )

if (CMAKE_CROSSCOMPILING)
else()
add_subdirectory ( tests )
endif()


