/**
 * dumpalloc.c
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

#include "../include/defs.h"
#include "../include/endian.h"
#include "buffered-writer.h"
#include "walk-stack.h"
#include "walk-python-stack.h"

#include <dlfcn.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <error.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>

#include <link.h>			/* for dl_iterate_phdr() */
#include <time.h>

#include <unwind.h>

//#define TRACE_MSG(...) fprintf(stderr, "libdumpalloc [TRACE]: "__VA_ARGS__); fflush(stderr);
#define TRACE_MSG(...)
#define INFO_MSG(...)  fprintf(stderr, "libdumpalloc [INFO] : "__VA_ARGS__); fflush(stderr);
#define ERROR_MSG(...) fprintf(stderr, "libdumpalloc [ERROR]: "__VA_ARGS__); fflush(stderr);

static walk_python_stack_fn walk_python_stack = NULL;

typedef void* (*malloc_fn)(size_t);

static malloc_fn real_malloc = NULL;

typedef void (*free_fn)(void*);

static free_fn real_free = NULL;

typedef void* (*calloc_fn)(size_t, size_t);

static calloc_fn real_calloc = NULL;

typedef void* (*realloc_fn)(void*, size_t);

typedef void* (*memalign_fn)(size_t, size_t);

static memalign_fn real_memalign = NULL;

static realloc_fn real_realloc = NULL;

typedef void* (*dlopen_fn)(const char*, int);

static dlopen_fn real_dlopen = NULL;


typedef void* (*PyObject_Malloc_fn)(size_t);

static PyObject_Malloc_fn real_PyObject_Malloc = NULL;

typedef void (*PyObject_Free_fn)(void*);

static PyObject_Free_fn real_PyObject_Free = NULL;


static uint32_t inited = 0;

static __thread size_t malloc_depth = 0;
static pthread_mutex_t mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

static int use_walk_stack = 0;

typedef struct {
	const void* start;
	const void* end;
	const char* name;
} known_object_t;


static known_object_t* known_objects = NULL;
static size_t num_known_objects = 0;
static size_t known_objects_capacity = 0;
static size_t known_objects_block_size = 64;

static int dump_fd = 1;
static buffered_writer* writer = NULL;

static void* dumpalloc_seg_start = NULL;
static void* dumpalloc_seg_end = NULL;

static char the_executable[4096];

static void on_failed_write(buffered_writer* writer, int ret, int error) {

	ERROR_MSG("Failed to write to fd (ret: %d, errno: %d).\nQuitting...\n",
		ret, error);
	exit(1);
}


static void open_socket(char* server_host_port) {

	size_t i;

	for (i=0; server_host_port[i] != ':' && server_host_port[i] != 0; ++i);

	if (server_host_port[i] != ':') {

		ERROR_MSG("Error! failed to parse server and port from DUMPALLOC_SERVER env var!\n");
		exit(1);
	}
	
	server_host_port[i] = 0;

	int port = atoi(server_host_port+i+1);

	INFO_MSG("host: %s, port: %d\n", server_host_port, port);

	int sockfd;
	struct sockaddr_in serv_addr;
	struct hostent* server;

	/* Create a socket point */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("ERROR opening socket.\n");
		exit(1);
	}

	TRACE_MSG("looking-up host...\n");
	server = gethostbyname(server_host_port);

	if (server == NULL) {
		ERROR_MSG("ERROR, no such host: %s\n", server_host_port);
		exit(1);
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, 
			(char *)&serv_addr.sin_addr.s_addr,
			server->h_length);

	serv_addr.sin_port = htons(port);

	INFO_MSG("connecting...\n");

	/* Now connect to the server */
	if (connect(sockfd,&serv_addr,sizeof(serv_addr)) < 0) {
		perror("ERROR connecting.\n");
		exit(1);
	}

	INFO_MSG("done.\n");
	dump_fd = sockfd;
}

static int write_uint32(buffered_writer* writer, const uint32_t i) {

	const uint32_t le = htole32(i);

	return writer->write(writer, &le, sizeof(le));
}

static int write_int32(buffered_writer* writer, const int32_t i) {

	return write_uint32(writer, i);
}

static int write_uint64(buffered_writer* writer, const uint64_t i) {

	const uint64_t le = htole64(i);

	return writer->write(writer, &le, sizeof(le));
}

static int write_addr(buffered_writer* writer, const void* addr) {

	return write_uint64(writer, (uint64_t)addr);
}


static uint64_t getTimestamp() {

	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec;
}

static void dump_header() {

	write_int32(writer, record_type_header);

	write_uint64(writer, getTimestamp());

	const uint32_t pid = (uint32_t)getpid();

	char buffer[512];

	bzero(buffer, sizeof(buffer));

	snprintf(buffer, sizeof(buffer), "/proc/%lu/cmdline", pid);

	FILE* proc_cmdline = fopen(buffer, "r");

	bzero(buffer, sizeof(buffer));

	if (proc_cmdline) {

		fread(buffer, 1, sizeof(buffer)-1, proc_cmdline);
	}

	uint32_t len = strnlen(buffer, sizeof(buffer)-1);

	fclose(proc_cmdline);

	write_uint32(writer, pid);

	write_uint32(writer, len);

	writer->write(writer, buffer, len);

	TRACE_MSG("dump_header(): %zd\n", len+4+8+4+4);
}



typedef struct {

	void* addr;
	const char* object;
	void* offset;
	void* seg_start_addr;
	void* seg_end_addr;

} sym_info_t;


static int check_next_lib(struct dl_phdr_info *info, size_t size, void* out) {

	sym_info_t* syminfo = (sym_info_t*)out;
/*
	TRACE_MSG("Checking lib: %s, lib addr: 0x%llx, fn addr: 0x%llx\n", info->dlpi_name, info->dlpi_addr, syminfo->addr);
*/
	if ((uint64_t)info->dlpi_addr > (uint64_t)syminfo->addr) {
		// not the lib we're looking for, keep looking.
		return 0;

	} else {

		// need to work out if this is the library.
		// walk through segment headers.

		size_t h = 0;
		for ( ; h < info->dlpi_phnum; ++h) {

			void* seg_addr = (void*)((uint64_t)info->dlpi_addr + (uint64_t)info->dlpi_phdr[h].p_vaddr);

			if (syminfo->addr >= seg_addr && syminfo->addr < seg_addr+info->dlpi_phdr[h].p_memsz) {

				// by jingo, I think we've found it!
				syminfo->offset = (void*)(info->dlpi_phdr[h].p_vaddr + (syminfo->addr - seg_addr));

				if (info->dlpi_name == NULL || info->dlpi_name[0] == 0) {

					if (info->dlpi_addr == 0) {
						// Probably the main executable.
						// Surprisingly, glibc doesn't give the name in this case, although
						// uClibC seems to manage!
						syminfo->object = the_executable;
					} else {
						// It's probably the virtual shared-object: linux-vdso.so
						syminfo->object = "??";
					}

				} else {
					syminfo->object = info->dlpi_name;
				}

				syminfo->seg_start_addr = seg_addr;
				syminfo->seg_end_addr = seg_addr+info->dlpi_phdr[h].p_memsz;
/*
				TRACE_MSG("pc: 0x%llx seg virt addr: 0x%llx lib base addr: 0x%llx calc seg addr: 0x%llx calc offset: 0x%llx \nObject: %s \n",
					(uint64_t)syminfo->addr, (uint64_t)info->dlpi_phdr[h].p_vaddr, (uint64_t)info->dlpi_addr, (uint64_t)seg_addr, (uint64_t)syminfo->offset, info->dlpi_name);
*/
				return 1;
			}
		}

		return 0;
	}
}

static int print_lib(struct dl_phdr_info *info, size_t size, void* out) {
	
	INFO_MSG("Lib: %s\n", info->dlpi_name);

	return 0;
}

static int print_loaded_libs() {

	dl_iterate_phdr(&print_lib, NULL);
}

static int resolve_addr(sym_info_t* out, void* addr) {

	out->addr = addr;
	out->object = NULL;
	out->offset = 0;

	dl_iterate_phdr(&check_next_lib, out);

	int found = (out->object != NULL?1:0);

	if (out->object == NULL || strlen(out->object) == 0) {
		out->object = "??";
	}

	return found;
}


static size_t object_lower_bound(const void* addr) {

	size_t s = 0;
	size_t e = num_known_objects;

	while (s != e) {

		size_t m = s+(e-s)/2;

		if (known_objects[m].start < addr) {
			s = m+1;
		} else {
			e = m;
		}
	}

	return s;
}


static const known_object_t* add_object(struct dl_phdr_info *info) {

	size_t h = 0;

	for ( ; h < info->dlpi_phnum; ++h) {

		// The assumption here is that we will only have one r-x loadable segment
		//
		if (info->dlpi_phdr[h].p_type == PT_LOAD && info->dlpi_phdr[h].p_flags == (PF_R | PF_X)) {

			const void* const seg_start = (const void*)(info->dlpi_addr + info->dlpi_phdr[h].p_vaddr);
			const void* const seg_end = (const void*)(seg_start + info->dlpi_phdr[h].p_memsz);

			size_t lower_bound = object_lower_bound(seg_start);

			// already added.
			if (lower_bound != num_known_objects && seg_start == known_objects[lower_bound].start) {
				return 0;
			}

			if (num_known_objects == known_objects_capacity) {

				size_t new_capacity = known_objects_capacity + known_objects_block_size;
				known_object_t* new_known_objects = realloc(known_objects, sizeof(known_object_t)*new_capacity);

				if ( ! new_known_objects ) {
					ERROR_MSG("Failed to reallocate known_objects!\n");
					exit(1);
				}

				known_objects = new_known_objects;
				known_objects_capacity = new_capacity;
			}

			if (lower_bound != num_known_objects) {
				memmove((known_objects+lower_bound+1), (known_objects+lower_bound),
					(num_known_objects-lower_bound)*sizeof(known_object_t));
			}

			const char* name = info->dlpi_name;

			if (name == NULL || name[0] == 0) {
				if (info->dlpi_addr == 0) {
					name = the_executable;
				} else {
					name = "??";
				}
			}

			known_object_t obj = { (const void*)seg_start, (const void*)seg_end, name };

			known_objects[lower_bound] = obj;

			num_known_objects++;

			return known_objects+lower_bound;
		}
	}

	return 0;
}


static int dump_object(void* const base_addr, const char* const name) {

	write_int32(writer, record_type_object);
	write_uint64(writer, getTimestamp());
	write_addr(writer, base_addr);
	const uint32_t len = strlen(name);
	write_uint32(writer, len);
	writer->write(writer, name, len);

	TRACE_MSG("dump_object(): %zd\n", (len+4+8+8+4));

	return 0;
}

static int dump_object_if_new(struct dl_phdr_info *info, size_t size, void* out) {

	const known_object_t* added = add_object(info);

	if ( added ) {

		const char* name = info->dlpi_name;

		if (name == NULL || name[0] == 0) {

			if (info->dlpi_addr == 0) {
				name = the_executable;
			} else {
				name = "??";
			}

		// `readalloc` will want absolute paths.
		} else if (name[0] != '/') {
			char tmp[4096];
			realpath(name, tmp);
			name = tmp;
		}

		return dump_object((void*)info->dlpi_addr, name);
	}

	return 0;
}

static int dump_new_objects() {

	dl_iterate_phdr(&dump_object_if_new, NULL);

	return 0;
}

/**
 * This is used to determine when walk-stack should stop backward-scanning looking for 
 * function prologue.
 * 
 * It tries to find the elf object that contains the starting address of the scan, and 
 * if found returns the starting address of that object.
 * 
 * @param ra current return-addr (the starting point of the backward-scan)
 * @return the earliest address that may be scanned.
 */ 
static const void* get_backward_scan_earliest_addr(const void* ra) {

	const size_t lower_bound = object_lower_bound(ra);

	if (lower_bound > 0 && known_objects[lower_bound-1].end >= ra) {
		return known_objects[lower_bound-1].start;
	}

	return ra;
}

static int dump_frame(void* ra, void* user_data) {

	TRACE_MSG("Frame: 0x%llx\n", (uint64_t)ra);

	size_t* num_frames = (size_t*)(user_data);

	// Skip calls to our internal fns. Don't want these showing-up in callstack.
	if (ra >= dumpalloc_seg_start && ra < dumpalloc_seg_end) {
		TRACE_MSG("Discarding frame\n");
		return 1;
	}

	++(*num_frames);

	write_addr(writer, ra);

	return 1;
}

static int dump_python_frame(const char* function, const char* source_file, const uint32_t line_no) {

	const uint32_t function_len = (function?strlen(function):0);
	write_uint32(writer, function_len);

	if (function_len) {
		writer->write(writer, function, function_len);
	}

	const uint32_t source_file_len = (source_file?strlen(source_file):0);
	write_uint32(writer, source_file_len);

	if (source_file_len) {
		writer->write(writer, source_file, source_file_len);
	}

	write_uint32(writer, line_no);

	return 1;
}


_Unwind_Reason_Code dump_unwind_frame(struct _Unwind_Context* ctx, void* user_data) {

	size_t* num_frames = (size_t*)user_data;

	void* ra = (void*)_Unwind_GetIP(ctx);

	TRACE_MSG("Frame: 0x%llx\n", (uint64_t)ra);

	// Skip calls to our internal fns. Don't want these showing-up in callstack.
	if (ra >= dumpalloc_seg_start && ra < dumpalloc_seg_end) {
		TRACE_MSG("Discarding frame: 0x%llx\n", ra);
		return _URC_NO_REASON;
	}

	write_addr(writer, ra);
	++(*num_frames);

	TRACE_MSG("dump_unwind_frame(): %zd\n", 8);

	return _URC_NO_REASON;
}

static void dump_alloc(void* addr, size_t size) {

	TRACE_MSG("dump_alloc() 0x%lx, %lu\n", addr, size);

	write_int32(writer, record_type_alloc);
	write_uint64(writer, getTimestamp());
	write_addr(writer, addr);
	write_uint32(writer, size);

	size_t num_frames = 0;

	if (use_walk_stack) {
		walk_stack(&dump_frame, &get_backward_scan_earliest_addr, &num_frames);
	} else {
		_Unwind_Backtrace(&dump_unwind_frame, &num_frames);
	}

	if (walk_python_stack) {
		write_addr(writer, (void*)1U);
		walk_python_stack(&dump_python_frame);
		write_uint32(writer, 0U);
	}

	// Sentinal marking end-of frames.
	write_addr(writer, 0U);

	writer->flush(writer);

	TRACE_MSG("dump_alloc(): %zd\n", (4+8+8+4+8));
}

static void dump_dealloc(void* addr) {

	TRACE_MSG("dump_dealloc() 0x%lx\n", addr);

	write_int32(writer, record_type_dealloc);
	write_uint64(writer, getTimestamp());
	write_addr(writer, addr);

	writer->flush(writer);

	TRACE_MSG("dump_dealloc(): %zd\n", (4+8+8));
}

static void get_executable_name(char* buffer, size_t buffer_len) {

	pid_t pid = getpid();

	bzero(buffer, buffer_len);

	char tmp[32];

	snprintf(tmp, sizeof(tmp), "/proc/%lu/exe", pid);

	TRACE_MSG("get_executable_name() resolving: %s\n", tmp);

	realpath(tmp, buffer);

	TRACE_MSG("get_executable_name() resolved to: %s\n", buffer);
}

static void resolve_pyobject_malloc() {

	TRACE_MSG("looking for PyObject_Malloc()...\n");

	real_PyObject_Malloc = (PyObject_Malloc_fn)dlsym(RTLD_NEXT, "PyObject_Malloc");

	if (!real_PyObject_Malloc) {

		INFO_MSG("Didn't find PyObject_Malloc(). OK, probably not running with Python.\n");
	}

	real_PyObject_Free = (PyObject_Free_fn)dlsym(RTLD_NEXT, "PyObject_Free");

	if (!real_PyObject_Free) {

		INFO_MSG("Didn't find PyObject_Free(). OK, probably not running with Python.\n");
	}
}

//__attribute__((constructor(1000)))
static void init() {

	pthread_mutex_lock(&mutex);

	TRACE_MSG("init()\n");

	++malloc_depth;

	if (getenv("DUMPALLOC_WALK_STACK")) {

		if (have_walk_stack) {
			INFO_MSG("I'm going to use MIPS-specific instr-scanning for unwinding stack.\n");
			use_walk_stack = 1;
		} else {
			ERROR_MSG("Ignoring `DUMPALLOC_WALK_STACK`. Instr-scanning not supported "
				"for this platform. Will use unwind instead.\n");
		}
	}

	TRACE_MSG("looking for calloc()...\n");

	real_calloc = (calloc_fn)dlsym(RTLD_NEXT, "calloc");

	if (!real_calloc) {
		ERROR_MSG("Failed to find real calloc!\n");
		exit(1);
	}

	get_executable_name(the_executable, sizeof(the_executable));

	TRACE_MSG("looking for malloc()...\n");

	real_malloc = (malloc_fn)dlsym(RTLD_NEXT, "malloc");

	if (!real_malloc) {
		ERROR_MSG("Failed to find real malloc!\n");
		exit(1);
	}

	TRACE_MSG("looking for free()...\n");

	real_free = (free_fn)dlsym(RTLD_NEXT, "free");

	if (!real_free) {
		ERROR_MSG("Failed to find real free!\n");
		exit(1);
	}

	TRACE_MSG("looking for realloc()...\n");

	real_realloc = (realloc_fn)dlsym(RTLD_NEXT, "realloc");

	if (!real_realloc) {
		ERROR_MSG("Failed to find real realloc!\n");
		exit(1);
	}

	real_memalign = (memalign_fn)dlsym(RTLD_NEXT, "memalign");

	if (!real_memalign) {
		ERROR_MSG("Failed to find real memalign! %s\n", dlerror());
		exit(1);
	}

	TRACE_MSG("looking-up address of own malloc()...\n");

	sym_info_t malloc_sym_info;

	if ( ! resolve_addr(&malloc_sym_info, &malloc) ) {

		ERROR_MSG("Failed to resolve address of my own malloc()!\n");
		exit(1);
	}

	dumpalloc_seg_start = malloc_sym_info.seg_start_addr;
	dumpalloc_seg_end = malloc_sym_info.seg_end_addr;

	TRACE_MSG("looking for dlopen()...\n");

	real_dlopen = (dlopen_fn)dlsym(RTLD_NEXT, "dlopen");

	if (!real_dlopen) {
		ERROR_MSG("Failed to find real `dlopen()`!\n");
		exit(1);
	}

	TRACE_MSG("Looking for `walk_python_stack()`...\n");

	walk_python_stack = (walk_python_stack_fn)dlsym(NULL, "walk_python_stack");

	if ( ! walk_python_stack ) {

		INFO_MSG("Failed to find `walk_python_stack()`. "
			"Python backtracing will be disabled.\n");
	} else {
		INFO_MSG("Python backtracing is enabled.\n");
	}

	INFO_MSG("Loaded libs: \n");

	print_loaded_libs();

	char* server_host_port = getenv("DUMPALLOC_SERVER");

	if (server_host_port) {

		open_socket(server_host_port);

	} else {

		char* output_file = getenv("DUMPALLOC_FILE");

		if (output_file) {

			if ((dump_fd = open(output_file, (O_CREAT | O_TRUNC | O_WRONLY), (S_IRUSR|S_IWUSR))) == -1) {
				ERROR_MSG("Failed to open output file for writing: %s\n", output_file);
				exit(1);
			}

		} else {

			ERROR_MSG("Error! you must set one of the environment variables: 'DUMPALLOC_SERVER' or "
				"'DUMPALLOC_FILE' to get any output!\n");
			exit(1);

		}
	}

	writer = buffered_writer_create(dump_fd, 1024);

	writer->on_error = &on_failed_write;

	TRACE_MSG("Dumping header...\n");
	dump_header();

	TRACE_MSG("Dumping objects...\n");
	dump_new_objects();

	TRACE_MSG("init() done.\n");

	--malloc_depth;

	pthread_mutex_unlock(&mutex);
}


#define INIT_ONCE \
	if (!__sync_val_compare_and_swap(&inited, 0, 1)) { \
		init(); \
	}


__attribute__((visibility("default")))
__attribute__((noinline))
void* dlopen(const char* name, int flag) {

	INIT_ONCE;

	TRACE_MSG("dlopen() %s\n", name);

	if ( ! writer ) {
		return real_dlopen(name, flag);
	}

	pthread_mutex_lock(&mutex);

	void* ret = real_dlopen(name, flag);

	dump_new_objects();

	pthread_mutex_unlock(&mutex);

	return ret;
}

__attribute__((visibility("default")))
__attribute__((noinline))
void* malloc(size_t size) {

	INIT_ONCE;

	TRACE_MSG("malloc(%zd)\n", size);

	if ( ! writer ) {
		return real_malloc(size);
	}

	// N.B. I hold the mutex across the actual allocation and deallocation as well as the dump
	// since it is possible that another thread could re-alloc at the same address before a free()
	// can be recorded (which would confuse the reader).
	//
	// This is not ideal, but will do for now.
	//
	pthread_mutex_lock(&mutex);

	++malloc_depth;

	void* addr = real_malloc(size);

	if ( malloc_depth == 1 ) {
		TRACE_MSG("Dumping malloc()...\n");
		dump_alloc(addr, size);
	} else {
		TRACE_MSG("Not dumping malloc. Depth is: %lu\n", malloc_depth);
	}

	pthread_mutex_unlock(&mutex);

	--malloc_depth;

	return addr;
}

__attribute__((visibility("default")))
__attribute__((noinline))
void free(void* ptr) {

	if ( ! ptr) return;

	INIT_ONCE;

	if ( ! writer ) {
		return real_free(ptr);
	}

	TRACE_MSG("free() : 0x%llx\n", (uint64_t)ptr);

	pthread_mutex_lock(&mutex);

	if ( ! malloc_depth++ ) {
		dump_dealloc(ptr);
	}

	real_free(ptr);
	
	pthread_mutex_unlock(&mutex);
	
	--malloc_depth;
}

__attribute__((visibility("default")))
__attribute__((noinline))
void* calloc(size_t nmemb, size_t size) {

	INIT_ONCE;

	TRACE_MSG("calloc()\n");

	if ( ! writer ) {
		if ( real_calloc ) {
			return real_calloc(nmemb, size);
		} else {
			return NULL;
		}
	}

	pthread_mutex_lock(&mutex);

	// implementation may call malloc()
	++malloc_depth;

	void* addr = NULL;

	if (!real_calloc) {
		TRACE_MSG("Real calloc() is NULL!\n");
	} else {
		addr = real_calloc(nmemb, size);
	}

	if ( malloc_depth == 1 ) {

		dump_alloc(addr, (nmemb * size));
	}

	TRACE_MSG("calloc() 0x%llx\n", (uint64_t)addr);

	pthread_mutex_unlock(&mutex);

	--malloc_depth;

	return addr;
}

__attribute__((visibility("default")))
__attribute__((noinline))
void* realloc(void* ptr, size_t size) {

	INIT_ONCE;

	TRACE_MSG("realloc()\n");

	if ( ! writer ) {
		return real_realloc(ptr, size);
	}

	pthread_mutex_lock(&mutex);

	// might call malloc()
	++malloc_depth;

	void* addr = real_realloc(ptr, size);

	if ( malloc_depth == 1 ) {

		if ( ptr && (addr || !size) ) {
			dump_dealloc(ptr);
		}

		if ( addr && size ) {
			dump_alloc(addr, size);
		}
	}

	TRACE_MSG("realloc() 0x%llx\n", (uint64_t)addr);

	pthread_mutex_unlock(&mutex);

	--malloc_depth;
	
	return addr;
}

__attribute__((visibility("default")))
__attribute__((noinline))
void * memalign(size_t boundary, size_t size)
{
	if( !writer ) {
		return real_memalign(boundary, size);
	}

	//this calls malloc, but we need to intercept it for lock reasons
	pthread_mutex_lock(&mutex);
	void* addr = real_memalign(boundary, size);
	pthread_mutex_unlock(&mutex);

	return addr;
}

__attribute__((visibility("default")))
__attribute__((noinline))
void* PyObject_Malloc(size_t size) {

	INIT_ONCE;

	TRACE_MSG("PyObject_Malloc(%zd)\n", size);

	if ( ! real_PyObject_Malloc ) {
		// FIXME: thread-safety!
		resolve_pyobject_malloc();
	}

	if ( ! writer ) {
		return real_PyObject_Malloc(size);
	}

	// N.B. I hold the mutex across the actual allocation and deallocation as well as the dump
	// since it is possible that another thread could re-alloc at the same address before a free()
	// can be recorded (which would confuse the reader).
	//
	// This is not ideal, but will do for now.
	//
	pthread_mutex_lock(&mutex);

	++malloc_depth;

	void* addr = real_PyObject_Malloc(size);

	if ( malloc_depth == 1 ) {
		TRACE_MSG("Dumping PyObject_Malloc()...\n");
		dump_alloc(addr, size);
	} else {
		TRACE_MSG("Not dumping PyObject_Malloc. Depth is: %lu\n", malloc_depth);
	}

	pthread_mutex_unlock(&mutex);

	--malloc_depth;

	return addr;
}


__attribute__((visibility("default")))
__attribute__((noinline))
void PyObject_Free(void* ptr) {

	if ( ! ptr) return;

	INIT_ONCE;

	if ( ! real_PyObject_Free ) {
		// FIXME: thread-safety!
		resolve_pyobject_malloc();
	}

	if ( ! writer ) {
		return real_PyObject_Free(ptr);
	}

	TRACE_MSG("PyObject_Free() : 0x%llx\n", (uint64_t)ptr);

	pthread_mutex_lock(&mutex);

	if ( ! malloc_depth++ ) {
		dump_dealloc(ptr);
	}

	real_PyObject_Free(ptr);

	pthread_mutex_unlock(&mutex);

	--malloc_depth;
}



// N.B. PyObject_Realloc is implemented in-terms-of either PyObject_Malloc() + PyObject_Free()
// or realloc(), so we don't bother to interpose it.

__attribute__((destructor))
static void cleanup() {

	TRACE_MSG("cleanup()\n");

	if (writer) {
		buffered_writer* tmp = writer;
		writer = NULL;
		tmp->flush(tmp);
		TRACE_MSG("Destroying writer. Written bytes: %zd, Flushed bytes: %zd.\n", tmp->total_requested, tmp->total_written);
		tmp->destroy(tmp);
	}
}


