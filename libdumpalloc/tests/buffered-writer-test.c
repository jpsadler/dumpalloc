/**
 * buffered-writer-test.c
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

#include "../src/buffered-writer.h"

#include <unistd.h>


const size_t write_buffer_capacity = 16U;
char* write_buffer;
size_t written_bytes = 0;

// interpose write.
ssize_t write(int fd, const void* buf, size_t count) {

	ssize_t can_write = min(write_buffer_capacity-written_bytes, count);

	memcpy(write_buffer+written_bytes, buf, can_write);
	written_bytes += can_write;

	return can_write;
}

static int test_write_larger_than_buffer() {

	const size_t capacity = 8U;

	buffered_writer* writer = buffered_writer_create(0, capacity);

	const char* msg = "0123456789";

	size_t len = strlen(msg);

	size_t written = writer->write(writer, msg, len);

	if ( written != len ) {
		fprintf(stderr, "Written: %lu, expected: %lu\n", written, len);
		return 1;
	}

	writer->destroy(writer);

	if ( memcmp(write_buffer, msg, len) ) {

		fprintf(stderr, "Written doesn't match expected: %s\n", write_buffer);
		return 2;
	}

	return 0;
}

static int test_write_smaller_than_buffer() {

	const size_t capacity = 8U;

	buffered_writer* writer = buffered_writer_create(0, capacity);

	const char* msg = "0123";

	size_t len = strlen(msg);

	size_t written = writer->write(writer, msg, len);

	if ( written != len ) {
		fprintf(stderr, "Written: %lu, expected: %lu\n", written, len);
		return 1;
	}

	writer->destroy(writer);

	if ( memcmp(write_buffer, msg, len) ) {

		fprintf(stderr, "Written doesn't match expected: %s\n", write_buffer);
		return 2;
	}

	return 0;
}

static int test_write_larger_than_fd_avail_space() {

	const size_t capacity = 32U;

	buffered_writer* writer = buffered_writer_create(0, capacity);

	const char* msg = "012345678909876543210123456789";

	size_t len = strlen(msg);

	size_t written = writer->write(writer, msg, len);

	if ( written != len ) {
		fprintf(stderr, "Written: %lu, expected: %lu\n", written, write_buffer_capacity);
		return 1;
	}

	if ( writer->flush(writer) > 0 ) {

		fprintf(stderr, "Didn't expect flush to flush any bytes. No avail space.\n");
		return 2;
	}

	writer->destroy(writer);

	if ( memcmp(write_buffer, msg, write_buffer_capacity) ) {

		fprintf(stderr, "Written doesn't match expected.\n");
		return 3;
	}

	return 0;

}



void setup() {

	write_buffer = malloc(write_buffer_capacity);
	bzero(write_buffer, write_buffer_capacity);
	written_bytes = 0;	
}

void teardown() {

	if (write_buffer) {
		free(write_buffer);
	}

}

typedef int (*test_fn)();

typedef struct {

	const char* name;
	test_fn fn;

} a_test;

#define TEST_FN(x) { #x, x }

int main(int argc, const char* argv[]) {

	a_test tests[] = {
		TEST_FN (test_write_larger_than_buffer),
		TEST_FN (test_write_smaller_than_buffer),
		TEST_FN (test_write_larger_than_fd_avail_space)
	};

	const size_t num_tests = (sizeof(tests)/sizeof(a_test));

	size_t i = 0;

	for (; i<num_tests; i++) {

		setup();
		if ( tests[i].fn() ) {
			fprintf(stderr, "FAIL: %s\n", tests[i].name);
		} else {
			fprintf(stderr, "OK: %s\n", tests[i].name);
		}
		teardown();
	}

	return 0;
}


