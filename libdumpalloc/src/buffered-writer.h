/**
 * buffered-writer.h
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

#ifndef BUFFERED_WRITER_H_
#define BUFFERED_WRITER_H_

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

struct _buffered_writer;

typedef int (*write_fn)(struct _buffered_writer*, const void*, size_t);
typedef int (*flush_fn)(struct _buffered_writer*);
typedef void (*destroy_fn)(struct _buffered_writer*);
typedef void (*on_error_fn)(struct _buffered_writer*, int, int);

typedef struct _buffered_writer {

	int fd;
	char* buffer;
	size_t capacity;
	size_t write_idx;
	size_t read_idx;

	write_fn write;
	flush_fn flush;
	destroy_fn destroy;
	on_error_fn on_error;

} buffered_writer;


static void buffered_writer_destroy(buffered_writer* writer) {

	if (writer->buffer) {
		writer->flush(writer);
		free(writer->buffer);
	}

	free(writer);
}

static ssize_t min(const ssize_t a, const ssize_t b) {

	return (a <= b?a:b);
}

static ssize_t buffered_writer_write(buffered_writer* writer, const void* bytes, const size_t count) {

	ssize_t total_written = 0;

	while (total_written < count) {

		ssize_t can_buffer = min((writer->capacity - writer->write_idx), 
			(count-total_written));

		if (can_buffer) {

			memcpy(writer->buffer+writer->write_idx, bytes+total_written, can_buffer);

			writer->write_idx += can_buffer;
			total_written += can_buffer;
		}

		if (writer->write_idx == writer->capacity) {

			ssize_t ret = writer->flush(writer);

			if (ret <= 0) {
				writer->on_error(writer, ret, errno);
				return ret;
			}
		}
	}

	return total_written;
}

static ssize_t buffered_writer_flush(buffered_writer* writer) {

	ssize_t bytes_written = 0;

	while (writer->read_idx < writer->write_idx &&
		(bytes_written = write(writer->fd, (writer->buffer + writer->read_idx), 
		(writer->write_idx - writer->read_idx))) > 0) {

		writer->read_idx += bytes_written;
	}

	if (bytes_written > 0) {
		writer->read_idx = writer->write_idx = 0;
	}

	return bytes_written;
}

static buffered_writer* buffered_writer_create(const int fd, const size_t capacity) {

	buffered_writer* writer = (buffered_writer*)malloc(sizeof(buffered_writer));

	writer->fd = fd;
	writer->capacity = capacity;
	writer->buffer = (char*)malloc(capacity);
	writer->write_idx = 0;
	writer->read_idx = 0;
	writer->write = &buffered_writer_write;
	writer->flush = &buffered_writer_flush;
	writer->destroy = &buffered_writer_destroy;
	writer->on_error = NULL;

	return writer;
}

#endif // BUFFERED_WRITER_H_

