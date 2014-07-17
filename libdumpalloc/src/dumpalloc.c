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


typedef void* (*malloc_fn)(size_t);

static malloc_fn real_malloc = NULL;

typedef void (*free_fn)(void*);

static free_fn real_free = NULL;

typedef void* (*calloc_fn)(size_t, size_t);

static calloc_fn real_calloc = NULL;

typedef void* (*realloc_fn)(void*, size_t);

static realloc_fn real_realloc = NULL;

typedef void* (*dlopen_fn)(const char*, int);

static dlopen_fn real_dlopen = NULL;

static uint32_t inited = 0;

static __thread size_t malloc_depth = 0;
static pthread_mutex_t mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

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


static void on_failed_write(buffered_writer* writer, int ret, int error) {

	fprintf(stderr, "Failed to write to fd (ret: %d, errno: %d).\nQuitting...\n",
		ret, error);

	exit(1);
}


static void open_socket(char* server_host_port) {

	size_t i;

	for (i=0; server_host_port[i] != ':' && server_host_port[i] != 0; ++i);

	if (server_host_port[i] != ':') {

		fprintf(stderr, "Error! failed to parse server and port from DUMPALLOC_SERVER env var!\n");
		exit(1);
	}
	
	server_host_port[i] = 0;

	int port = atoi(server_host_port+i+1);

	fprintf(stderr, "host: %s, port: %d\n", server_host_port, port);

	int sockfd;
	struct sockaddr_in serv_addr;
	struct hostent* server;

	/* Create a socket point */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("ERROR opening socket.\n");
		exit(1);
	}

	fprintf(stderr, "looking-up host...\n");
	server = gethostbyname(server_host_port);

	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host: %s\n", server_host_port);
		exit(1);
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, 
			(char *)&serv_addr.sin_addr.s_addr,
			server->h_length);

	serv_addr.sin_port = htons(port);

	fprintf(stderr, "connecting...\n");

	/* Now connect to the server */
	if (connect(sockfd,&serv_addr,sizeof(serv_addr)) < 0) {
		perror("ERROR connecting.\n");
		exit(1);
	}

	fprintf(stderr, "done.\n");
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

	if ((uint32_t)info->dlpi_addr > (uint32_t)syminfo->addr) {

		// not the lib we're looking for, keep looking.
		return 0;

	} else {

		// need to work out if this is the library.
		// walk through segment headers.

		size_t h = 0;
		for ( ; h < info->dlpi_phnum; ++h) {

			void* seg_addr = (void*)((uint32_t)info->dlpi_addr + (uint32_t)info->dlpi_phdr[h].p_vaddr);

			if (syminfo->addr >= seg_addr && syminfo->addr < seg_addr+info->dlpi_phdr[h].p_memsz) {

				// by jingo, I think we've found it!
				syminfo->offset = (void*)(info->dlpi_phdr[h].p_vaddr + (syminfo->addr - seg_addr));

				syminfo->object = info->dlpi_name;
				syminfo->seg_start_addr = seg_addr;
				syminfo->seg_end_addr = seg_addr+info->dlpi_phdr[h].p_memsz;
/*
				fprintf(stderr, "pc: 0x%x seg virt addr: 0x%x lib base addr: 0x%x calc seg addr: 0x%x calc offset: 0x%x \nObject: %s \n", 
					(uint32_t)syminfo->addr, (uint32_t)info->dlpi_phdr[h].p_vaddr, (uint32_t)info->dlpi_addr, (uint32_t)seg_addr, (uint32_t)syminfo->offset, info->dlpi_name);
*/
				return 1;
			}
		}

		return 0;
	}
}

static int print_lib(struct dl_phdr_info *info, size_t size, void* out) {
	
	fprintf(stderr, "Lib: %s\n", info->dlpi_name);

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
					fprintf(stderr, "Failed to reallocate known_objects!\n");
					exit(1);
				}

				known_objects = new_known_objects;
				known_objects_capacity = new_capacity;
			}

			if (lower_bound != num_known_objects) {
				memmove((known_objects+lower_bound+1), (known_objects+lower_bound),
					(num_known_objects-lower_bound)*sizeof(known_object_t));
			}

			known_object_t obj = { (const void*)seg_start, (const void*)seg_end, info->dlpi_name };

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

	return 0;
}

static int dump_object_if_new(struct dl_phdr_info *info, size_t size, void* out) {

	//if ( add_object((void*)info->dlpi_addr) ) {

	const known_object_t* added = add_object(info);

	if ( added ) {
//		return dump_object((void*)added->start, info->dlpi_name);
		return dump_object((void*)info->dlpi_addr, info->dlpi_name);
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

	size_t* num_frames = (size_t*)(user_data);

	// Skip calls to our internal fns. Don't want these showing-up in callstack.
	if (ra >= dumpalloc_seg_start && ra < dumpalloc_seg_end) return 1;

	++(*num_frames);

	write_addr(writer, ra);

	return 1;
}


static void dump_alloc(void* addr, size_t size) {

	//fprintf(stderr, "dump_alloc() 0x%lx, %lu\n", addr, size);
	write_int32(writer, record_type_alloc);
	write_uint64(writer, getTimestamp());
	write_addr(writer, addr);
	write_uint32(writer, size);

	size_t num_frames = 0;

	walk_stack(&dump_frame, &get_backward_scan_earliest_addr, &num_frames);
	
	// Sentinal marking end-of frames.
	write_addr(writer, 0U);

	writer->flush(writer);
}

static void dump_dealloc(void* addr) {

	//fprintf(stderr, "dump_dealloc() 0x%lx\n", addr);
	write_int32(writer, record_type_dealloc);
	write_uint64(writer, getTimestamp());
	write_addr(writer, addr);

	writer->flush(writer);
}


//__attribute__((constructor(1000)))
static void init() {

	pthread_mutex_lock(&mutex);

	fprintf(stderr, "init()\n");

	++malloc_depth;

	real_dlopen = (dlopen_fn)dlsym(RTLD_NEXT, "dlopen");

	if (!real_dlopen) {
		fprintf(stderr, "Failed to find real dlopen!\n");
		exit(1);
	}

	real_malloc = (malloc_fn)dlsym(RTLD_NEXT, "malloc");

	if (!real_malloc) {
		fprintf(stderr, "Failed to find real malloc!\n");
		exit(1);
	}

	real_free = (free_fn)dlsym(RTLD_NEXT, "free");

	if (!real_free) {
		fprintf(stderr, "Failed to find real free!\n");
		exit(1);
	}

	real_calloc = (calloc_fn)dlsym(RTLD_NEXT, "calloc");

	if (!real_calloc) {
		fprintf(stderr, "Failed to find real calloc!\n");
		exit(1);
	}

	real_realloc = (realloc_fn)dlsym(RTLD_NEXT, "realloc");

	if (!real_realloc) {
		fprintf(stderr, "Failed to find real realloc!\n");
		exit(1);
	}

	sym_info_t malloc_sym_info;

	if ( ! resolve_addr(&malloc_sym_info, &malloc) ) {

		fprintf(stderr, "Failed to resolve address of my own malloc()!\n");
		exit(1);
	}

	dumpalloc_seg_start = malloc_sym_info.seg_start_addr;
	dumpalloc_seg_end = malloc_sym_info.seg_end_addr;


	fprintf(stderr, "Loaded libs: \n");

	print_loaded_libs();

	char* server_host_port = getenv("DUMPALLOC_SERVER");

	if (server_host_port) {

		open_socket(server_host_port);

	} else {

		char* output_file = getenv("DUMPALLOC_FILE");

		if (output_file) {

			if ((dump_fd = open(output_file, (O_CREAT | O_TRUNC | O_WRONLY))) == -1) {
				fprintf(stderr, "Failed to open output file for writing: %s\n", output_file);
				exit(1);
			}
		} else {
			fprintf(stderr, "Error! you must set one of the environment variables: 'DUMPALLOC_SERVER' or "
				"'DUMPALLOC_FILE' to get any output!\n");
			exit(1);
		}
	}

	writer = buffered_writer_create(dump_fd, 1024);

	writer->on_error = &on_failed_write;

	dump_header();

	dump_new_objects();

	fprintf(stderr, "init() done.\n");

	fflush(stderr);

	--malloc_depth;

	pthread_mutex_unlock(&mutex);
}


#define INIT_ONCE \
	if (!__sync_val_compare_and_swap(&inited, 0, 1)) { \
		init(); \
	}


__attribute__((visibility("default")))
void* dlopen(const char* name, int flag) {

	INIT_ONCE;

	fprintf(stderr, "dlopen() %s\n", name);
	pthread_mutex_lock(&mutex);

	void* ret = real_dlopen(name, flag);

	dump_new_objects();

	pthread_mutex_unlock(&mutex);

	return ret;
}

__attribute__((visibility("default")))
void* malloc(size_t size) {

	INIT_ONCE;

	//fprintf(stderr, "malloc()\n");
//	fflush(stderr);

	// N.B. I hold the mutex across the actual allocation and deallocation as well as the dump
	// since it is possible that another thread could re-alloc at the same address before a free()
	// can be recorded (which would confuse the reader).
	//
	// This is not ideal, but will do for now.
	//
	pthread_mutex_lock(&mutex);

	void* addr = real_malloc(size);

	if ( ! malloc_depth++ ) {
		
		dump_alloc(addr, size);
	}

	pthread_mutex_unlock(&mutex);

	//fprintf(stderr, "malloc 0x%lx, %lu\n", (uint32_t)addr, size);
//	fflush(stderr);

	--malloc_depth;

	return addr;
}

__attribute__((visibility("default")))
void free(void* ptr) {

	if ( ! ptr) return;

	INIT_ONCE;

	//fprintf(stderr, "free() : 0x%lx\n", (uint32_t)ptr);
	//fflush(stderr);

	pthread_mutex_lock(&mutex);

	if ( ! malloc_depth++ ) {
		
		dump_dealloc(ptr);
	}

	real_free(ptr);
	
	pthread_mutex_unlock(&mutex);
	
	--malloc_depth;
}

__attribute__((visibility("default")))
void* calloc(size_t nmemb, size_t size) {

	INIT_ONCE;

	//fprintf(stderr, "calloc()\n");
//	fflush(stderr);
	
	pthread_mutex_lock(&mutex);

	// implementation may call malloc()
	++malloc_depth;

	void* addr = real_calloc(nmemb, size);

	if ( malloc_depth == 1 ) {

		dump_alloc(addr, (nmemb * size));
	}

	//fprintf(stderr, "calloc() 0x%lx\n", (uint32_t)addr);

	pthread_mutex_unlock(&mutex);

	--malloc_depth;

	return addr;
}

__attribute__((visibility("default")))
void* realloc(void* ptr, size_t size) {

	INIT_ONCE;

	//fprintf(stderr, "realloc()\n");
//	fflush(stderr);

	pthread_mutex_lock(&mutex);

	// might call malloc()
	++malloc_depth;

	void* addr = real_realloc(ptr, size);

	if ( malloc_depth == 1 ) {

		if ( addr ) {

			if ( ptr ) {
				dump_dealloc(ptr);
			}

			if ( size ) {
				dump_alloc(addr, size);
			}
		}
	}

	//fprintf(stderr, "realloc() 0x%lx\n", (uint32_t)addr);

	pthread_mutex_unlock(&mutex);

	--malloc_depth;
	
	return addr;
}

