# About

*Warning: this software is very-much a work-in-progress at the moment, and the code
is alpha-quality, (at best). This is not production code. It has very little in the way
of tests, and is bound to be full of bugs.*

## libdumpalloc

`libdumpalloc` is a tool for monitoring and debugging (heap) memory usage on 
embedded Linux devices. It currently supports only MIPS devices, but may be 
enhanced in the future to support other architectures. 

`libdumpalloc` is intended to be used on the target device and is intended to 
be LD_PRELOADed when started the program to be monitored. 

Like many other `malloc` debuggers, it works by interposing `malloc()`, `realloc()`, 
`calloc()`, `free()` etc., to track memory allocation and deallocation events. 

Additionally, it generates a stacktrace for each allocation/deallocation, which 
is then either logged to a file, or to a remote process, via a TCP socket. 

By default `libdumpalloc` uses GCC intrinsic unwind support. However, on MIPS
platforms, an alternative unwinder is available which uses instruction-scanning
with a termination heuristic. This is an inherently processor-specific technique,
and is only available for MIPS. However, an advantage of this technique is that
it works quite well with release builds, and doesn't require unwind tables.

To enable this alternative unwinder set the environment variable:

	DUMPALLOC_WALK_STACK=1

prior to LD_PRELOADING `libdumpalloc.so`


## readalloc

`readalloc` is a program that is intended to be run on a Linux development PC, 
and is capable of reading the data gathered by `libdumpalloc`, resolving 
addresses to symbol names, and producing reports. 

Currently, `readalloc` can generate reports in [Callgrind][] format, which can be 
read using [KCachegrind][], among other tools.

`libdumpalloc` doesn't require `readalloc` to operate, rather it is one tool that 
can be used with the generated output.


# Licensing

`libdumpalloc` is licensed under LGPL. See `libdumpalloc/COPYING`.

`readalloc` is licensed under GPL3. See `readalloc/COPYING`.


# Building

## Prerequisities

Dependencies are deliberately kept to a minimum.

[CMake][] is required for building.

`libdumpalloc` requires only a working toolchain, C library and `libpthread`.

`readalloc` requires [Boost][] and [ZLib][] to be installed on the build machine. 
It also uses `BFD` (part of GNU [binutils]), but the CMake build takes care of 
downloading and building this.

## Building `libdumpalloc.so`

It is usual to cross-compile `libdumpmalloc.so` for the embedded device. In order
to do this, it is necessary to feed CMake a toolchain file appropriate for the 
toolchain you are using. For example, `my-mips-toolchain.cmake` might look 
something like this:

		SET(CMAKE_SYSTEM_NAME Linux)
		SET(CMAKE_SYSTEM_VERSION 1)

		# specify the cross compiler
		SET(CMAKE_C_COMPILER   /opt/toolchains/my-mips-toolchain/bin/mipsel-linux-gcc)
		SET(CMAKE_CXX_COMPILER /opt/toolchains/my-mips-toolchain/bin/mipsel-linux-g++)

		# where is the target environment 
		SET(CMAKE_FIND_ROOT_PATH  /opt/staging-rootfs)

		# search for programs in the build host directories
		SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

		# for libraries and headers in the target directories
		SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
		SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)


Assuming the `dumpalloc` source directory is in the current directory we then do
this to build the library:

		mkdir dumpalloc-build-target
		cd dumpalloc-build-target
		cmake -DCMAKE_TOOLCHAIN_FILE=my-mips-toolchain.cmake ../dumpalloc/libdumpalloc
		make


## Building and running `libdumpalloc` tests

Obviously, a native build is required in order to run the tests:

		mkdir dumpalloc-build-host
		cd dumpalloc-build-host
		cmake ../dumpalloc/libdumpalloc
		make


## Building `readalloc`

		mkdir readalloc-build-host
		cd readalloc-build-host
		cmake ../dumpalloc/readalloc
		make

This will also build download the binutils source package and build BFD.

The resulting executable can be found in `dumpalloc-build-host/readalloc/`


# Usage

## Take a copy of the root filesystem from the embedded device

In order for `readalloc` to be able to decode the stack frames it receives from
`libdumpalloc`, it must at least have access to the executable that is being 
monitored, and all libraries that are used by this executable. Since `readalloc`
will be running on a PC, the simplest thing to do is to just take a local copy 
of the entire rootfs from the target device.

## Dumping directly to readalloc over a socket

First, on the PC, launch `readalloc` on the PC. Since we want `libdumpalloc` 
to send the captured data directly to `readalloc` we need a listening socket, so
we do this:

		nc -lp 7000 | readalloc /path/to/device/rootfs

`readalloc` itself doesn't listen on a socket. We instead are using `netcat` (`nc`)
to do this for us. `readalloc` then just reads from `stdin`. In this example
we're using port 7000. `/path/to/device/rootfs` should be wherever you copied the 
root filesystem to.


Next, on the target device, launch the program to be monitored like this:

		DUMPALLOC_SERVER=mypc:7000 LD_PRELOAD=/some/path/libdumpalloc.so myprogram

Where `mypc` is the hostname, or address, of the PC running `readalloc`, and 
`myprogram` is the program you wish to monitor.

`libdumpalloc` will now begin capturing allocation events and sending them to 
the remote `readalloc`, which will maintain a live view of current allocations.

To generate a Callgrind output file, send SIGINT or SIGTERM to `readalloc`. On
exiting, it will write a file named like: `myprogram.1234.callgrind`, where `1234`
is the PID of the remote process.

## Dumping to a file and processing offline

Sometimes there is no network connection between the target device and the PC. 
In this situation, `libdumpalloc` can be told to dump directly to a file. Launch
it like this:

		DUMPALLOC_FILE=/some/file LD_PRELOAD=/some/path/libdumpalloc.so myprogram

Then, assuming the file can somehow later be transferred to the PC, it can be
processed by `readalloc` by doing:

		cat /some/file | readalloc /path/to/device/rootfs

## Dumping to a file and gzipping the output

Dump files quickly grow in size, but benefit greatly from compression. In order
to keep `libdumpalloc` as simple as possible, it doesn't implement any compression
of dump files. However, if you have `netcat` and `gzip` on the target you can do
this:

		nc -lp 7000 | gzip -c > /somepath/myprog.dump.gz &

Followed by:

		DUMPALLOC_SERVER=localhost:7000 LD_PRELOAD=/some/path/libdumpalloc.so myprogram


Then, once the resulting file has been copied to the PC, do:

		gunzip -cd /somepath/myprog.dump.gz | readalloc /path/to/device/rootfs


[Callgrind]:	http://valgrind.org/docs/manual/cl-manual.html
[KCachegrind]:	http://kcachegrind.sourceforge.net/html/Home.html
[CMake]:	http://www.cmake.org
[Boost]:	http://www.boost.org
[ZLib]:	http://www.zlib.net/
[binutils]:	https://sourceware.org/binutils

 
