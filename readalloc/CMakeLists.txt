##
# CMakeLists.txt
#
# Copyright (c) 2014 John Sadler <deathofathousandpapercuts@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
##

cmake_minimum_required ( VERSION 2.6 ) 
project ( READALLOC )

find_package(Boost REQUIRED COMPONENTS program_options)
include_directories(${Boost_INCLUDE_DIRS})

include(ExternalProject)
ExternalProject_Add(
	binutils-2.24
	URL http://ftp.gnu.org/gnu/binutils/binutils-2.24.tar.gz
    PATCH_COMMAND patch -p1 < ${CMAKE_CURRENT_SOURCE_DIR}/fix-libiberty-install.patch
	CONFIGURE_COMMAND <SOURCE_DIR>/bfd/configure --enable-targets=mipsel --disable-nls --prefix=<INSTALL_DIR>
	INSTALL_DIR "bfd"
)

#now also build libiberty from the same sources
ExternalProject_Add_Step(
    binutils-2.24
    libiberty-mkdir
    COMMAND mkdir -p libiberty_build
    DEPENDEES install
)

ExternalProject_Add_Step(
    binutils-2.24
    libiberty-configure
    COMMAND <SOURCE_DIR>/libiberty/configure --prefix=<INSTALL_DIR> --enable-install-libiberty
    DEPENDEES libiberty-mkdir
    WORKING_DIRECTORY libiberty_build
)

ExternalProject_Add_Step(
    binutils-2.24
    libiberty-make
    COMMAND ${CMAKE_MAKE_PROGRAM}
    DEPENDEES libiberty-configure
    WORKING_DIRECTORY libiberty_build
)

ExternalProject_Add_Step(
    binutils-2.24
    libiberty-install
    COMMAND ${CMAKE_MAKE_PROGRAM} install
    DEPENDEES libiberty-make
    WORKING_DIRECTORY libiberty_build
)

ExternalProject_Get_Property( binutils-2.24 install_dir )

include_directories("${install_dir}/include" "${install_dir}/include/libiberty")
set( CMAKE_CXX_FLAGS " ${CMAKE_CXX_FLAGS} -D_GNU_SOURCE=1 -D__STDC_LIMIT_MACROS=1 -O3 -fvisibility=hidden -fPIC -pthread " )

set( CMAKE_EXE_LINKER_FLAGS " -L${install_dir}/lib -Wl,-as-needed " )

add_executable ( readalloc src/readalloc.cpp src/Symbol.cpp src/SourceFile.cpp src/Object.cpp src/CallSite.cpp )
add_dependencies ( readalloc binutils-2.24 )
target_link_libraries( readalloc bfd iberty z dl c boost_program_options  )

