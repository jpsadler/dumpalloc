/**
 * readalloc.cpp
 *
 * Copyright (c) 2014 John Sadler <deathofathousandpapercuts@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "UniqueString.h"
#include "Symbol.h"
#include "SourceFile.h"
#include "Object.h"
#include "CallStack.h"
#include "CallSite.h"
#include "Objects.h"
#include "Alloc.h"

#include "../../libdumpalloc/include/defs.h"
#include "../../libdumpalloc/include/endian.h"

#include <map>
#include <set>
#include <string>
#include <vector>
#include <algorithm>
#include <memory>
#include <boost/noncopyable.hpp>
#include <boost/optional.hpp>
#include <boost/ptr_container/ptr_map.hpp>
#include <boost/ptr_container/ptr_vector.hpp>
#include <boost/foreach.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/unordered_map.hpp>
#include <boost/functional/hash.hpp>
#include <boost/scoped_array.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/bind.hpp>

#include <set>
#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#define HAVE_DECL_BASENAME 1
#include <libiberty.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>

#define PACKAGE // to avoid config.h include error in bfd.h
#include <bfd.h>


namespace po = boost::program_options;


static const int read_fd = 0;

static std::string rootfs_dir;

static volatile bool keep_reading = true;

static std::string remote_command;
static std::string remote_program;
static uint32_t remote_pid;
static uint64_t start_time;
static uint64_t latest_alloc_timestamp;

static uint64_t active_alloc_count = 0;
static uint64_t active_alloc_total_cost = 0;

static SourceFile* lookup_or_create_sourcefile(const std::string& name);


typedef Objects known_objects_t;

static known_objects_t known_objects;


typedef boost::ptr_map<const std::string, SourceFile> source_file_map_t;

static source_file_map_t known_source_files;


struct Sample {

	Sample() :
		sample_time(0),
		alloc_count(0),
		total_cost(0) {
	}

	Sample(const uint64_t sample_time_, const uint64_t alloc_count_, const uint64_t total_cost_) :
		sample_time(sample_time_),
		alloc_count(alloc_count_),
		total_cost(total_cost_) {
	}

	uint64_t sample_time;
	uint64_t alloc_count;
	uint64_t total_cost;
};

static std::vector<Sample> samples;

uint32_t sample_interval_secs = 0;


static SourceFile* lookup_or_create_sourcefile(const std::string& name) {

	source_file_map_t::iterator i = known_source_files.lower_bound(name);

	if (i != known_source_files.end() && name == i->first) {

		return i->second;

	} else {

		SourceFile* source_file = new SourceFile(name);

		known_source_files.insert(name, source_file);

		return source_file;
	}
}


static void print_stack(const CallStack& stack) {

	BOOST_FOREACH(const CallSite* cs, stack) {

		fprintf(stderr, "0x%llx, %s %s\n", cs->addr, cs->from_symbol.get_name(), cs->from_symbol.object.name.c_str());
		fflush(stderr);
	}
}


typedef boost::ptr_map<const addr_t, Alloc> alloc_map_t;

static alloc_map_t known_allocs;

int apply_alloc_cost (Alloc& alloc) { 

	CallSite* prev_callsite = 0;

	BOOST_FOREACH(CallSite* site, alloc.stack) {

		++site->times_called;
		site->cum_alloc += alloc.size;

		if (prev_callsite) {
			OnwardCall& onward_call = site->add_onward_call(prev_callsite);
			++onward_call.times_called;
			onward_call.cum_alloc += alloc.size;
		}

		prev_callsite = site;
	}

	++active_alloc_count;
	active_alloc_total_cost += alloc.size;

	return 0;
}

void clear_all_alloc_costs() {

	BOOST_FOREACH(Object* object, known_objects) {
		object->clear_callsite_costs();
	}

	active_alloc_count = 0;
	active_alloc_total_cost = 0;
}


void apply_alloc_costs(const uint64_t starting_timestamp, const uint64_t ending_timestamp) {

	BOOST_FOREACH(typename alloc_map_t::reference alloc, known_allocs) {
		if (alloc.second->alloc_time >= starting_timestamp && alloc.second->alloc_time < ending_timestamp) {
			apply_alloc_cost(*alloc->second);
		}
	}
}


static void update_samples(const uint64_t time_offset, const int32_t count_delta, const int32_t cost_delta) {

	if (sample_interval_secs) {

		// First thing: let's work-out whether we need to create a new sample.
		Sample& current_sample = samples.back();

		if ((time_offset - current_sample.sample_time) > sample_interval_secs) {
			const uint64_t new_sample_time = (time_offset / sample_interval_secs) * sample_interval_secs;
			current_sample.sample_time = new_sample_time;
			samples.push_back(Sample(new_sample_time, current_sample.alloc_count+count_delta, current_sample.total_cost+cost_delta));
		} else {
			current_sample.alloc_count += count_delta;
			current_sample.total_cost += cost_delta;
		}
	}
}


static Alloc* add_alloc(const uint64_t alloc_time, const addr_t addr, const uint32_t size, CallStack& stack) {

	std::auto_ptr<Alloc> alloc(new Alloc(alloc_time, addr, size, stack));
	Alloc* raw = alloc.get();

	int32_t count_delta = 1;
	int32_t cost_delta = size;

	typename alloc_map_t::iterator existing = known_allocs.find(addr);

	if (existing != known_allocs.end()) {

		fprintf(stderr, "Warning: Duplicate allocation address: 0x%llx detected. Something is very wrong...\n", addr);
		typename alloc_map_t::auto_type old = known_allocs.replace(existing, alloc);

		if (old) {
			count_delta = 0;
			cost_delta -= old->size;
		}

	} else {

		known_allocs.insert(addr, alloc);
	}

	latest_alloc_timestamp = alloc_time;

	update_samples(alloc_time, count_delta, cost_delta);

	return raw;
}

static bool delete_alloc(const uint64_t dealloc_time, const addr_t addr) {

	alloc_map_t::iterator found_at = known_allocs.find(addr);

	if (found_at != known_allocs.end()) {

		known_allocs.erase(found_at);

		update_samples(dealloc_time, -1, (0-found_at->second->size));

		return true;
	}

	return false;
}


static int read_string(int fd, char* buffer, size_t expected_len) {

	int ret = 0;
	int total_read = 0;

	while (expected_len > 0 && (ret = read(fd, buffer+total_read, expected_len)) > 0) {

		expected_len -= ret;

		total_read += ret;
	}

	return total_read;
}


static int read(int fd, uint32_t& i) {

	int bytes_read = read_string(fd, (char*)&i, sizeof(i));

	if (bytes_read == sizeof(i)) {
		i = le32toh(i);
	}

	return bytes_read;
}

static int read(int fd, int32_t& i) {

	uint32_t u;

	int bytes_read = read_string(fd, (char*)&u, sizeof(u));

	if (bytes_read == sizeof(u)) {
		i = (int32_t)le32toh(u);
	}

	return bytes_read;
}

static int read(int fd, uint64_t& i) {

	int bytes_read = read_string(fd, (char*)&i, sizeof(i));

	if (bytes_read == sizeof(i)) {

		i = le64toh(i);
	}

	return bytes_read;
}


static int read_header() {

	if (read(read_fd, start_time) != sizeof(start_time)) {
		fprintf(stderr, "Failed to read start time.\n");
	}

	if (read(read_fd, remote_pid) != sizeof(remote_pid)) {
		fprintf(stderr, "Failed to read pid.\n");
		return 1;
	}

	uint32_t command_len = 0;

	if (read(read_fd, command_len) != sizeof(command_len)) {
		return 1;
	}

	remote_command.resize(command_len);

	if (read_string(read_fd, &remote_command[0], command_len) != command_len) {
		return 1;
	}



	if (remote_command.size()) {

		size_t space_at = remote_command.find_first_of(" ");

		if (space_at == remote_command.npos) space_at = remote_command.length();

		size_t last_slash_at = remote_command.find_last_of("/", space_at);

		if (last_slash_at == remote_command.npos) last_slash_at = 0;

		remote_program = remote_command.substr(last_slash_at+1, (space_at-last_slash_at-1));
	} else {
		remote_program = "unknown";
	}

	return 0;
}


static int read_object() {

	uint64_t time_added;
	addr_t base_vaddr;

	//fprintf(stderr, "read_object()\n");

	if (read(read_fd, time_added) != sizeof(time_added)) {
		fprintf(stderr, "Failed to read time object was added.\n");
		return 1;
	}

	if (read(read_fd, base_vaddr) != sizeof(base_vaddr)) {
		fprintf(stderr, "Failed to read object base vaddr.\n");
		return 1;
	}

	uint32_t name_len;

	if (read(read_fd, name_len) != sizeof(name_len)) {
		return 1;
	}

	char name[name_len+1];

	if (read_string(read_fd, name, name_len) != name_len) {
		fprintf(stderr, "Failed to read object name. Name len: %lu\n", name_len);
		return 1;
	}

	name[name_len] = 0;

	//fprintf(stderr, "base_vaddr: 0x%llx, name: %s\n", base_vaddr, name);

	known_objects.create(time_added-start_time, base_vaddr, name, name_len);

	return 0;
}

static int read_python_frames(CallStack& stack) {

	PythonObject& object = known_objects.get_python_object();

	while ( true ) {

		uint32_t function_len;

		if (read(read_fd, function_len) != sizeof(function_len)) {
			fprintf(stderr, "Failed to read Python frame!\n");
			return 1;
		}

		if ( ! function_len ) {
			break;
		}

		char function[function_len+1];

		if (read_string(read_fd, function, function_len) != function_len) {
			fprintf(stderr, "Failed to read Python frame (function name)\n");
			return 1;
		}

		function[function_len] = 0;

		uint32_t source_file_len;

		if (read(read_fd, source_file_len) != sizeof(source_file_len)) {
			fprintf(stderr, "Failed to read Python frame (source file)\n");
			return 1;
		}

		char source_file[source_file_len+1];

		source_file[0] = 0;

		if (source_file_len && read_string(read_fd, source_file, source_file_len) != source_file_len) {
			fprintf(stderr, "Failed to read Python frame (source file)\n");
			return 1;
		}

		source_file[source_file_len] = 0;

		uint32_t line_no;

		if (read(read_fd, line_no) != sizeof(line_no)) {
			fprintf(stderr, "Failed to read Python frame (line no.)\n");
			return 1;
		}

		CallSite* call_site = object.lookup_or_create_callsite(function, source_file, line_no, &lookup_or_create_sourcefile);

		stack.add_frame(call_site);
	}

	return 0;
}


static int read_alloc() {

	uint64_t alloc_time;
	addr_t addr;
	uint32_t size;

	if (read(read_fd, alloc_time) != sizeof(alloc_time) ||
		read(read_fd, addr) != sizeof(addr) ||
		read(read_fd, size) != sizeof(size)) {

		return 1;
	}

	// read the call stack 

	CallStack stack;

	while ( true ) {

		addr_t ra;

		if (read(read_fd, ra) != sizeof(ra)) {
			fprintf(stderr, "Failed to read frame addr!\n");
			return 1;
		}

		if (ra == 0) break;

		if (ra == 1) {
			read_python_frames(stack);
		} else {

			Object* object = known_objects.lookup_by_ra(ra);

			CallSite* call_site = object->lookup_or_create_callsite(ra, &lookup_or_create_sourcefile, rootfs_dir);

			stack.add_frame(call_site);
		}
	}

	add_alloc(alloc_time-start_time, addr, size, stack);

	return 0;
}


static int read_dealloc() {

	uint64_t dealloc_time;
	addr_t addr;

	if (read(read_fd, dealloc_time) != sizeof(dealloc_time) ||
		read(read_fd, addr) != sizeof(addr)) {
		return 1;
	}

	//fprintf(stderr, "read_dealloc() 0x%llx\n", addr);

	if ( ! delete_alloc((dealloc_time-start_time), addr) ) {
		fprintf(stderr, "Cannot record deletion. Failed to find alloc with addr: 0x%llx\n", addr);
	}

	return 0;
}


typedef int (*read_fn)();

static int start_reading() {

	uint64_t records_consumed = 0;

	int32_t rec_type = 0;

	int ret = 0;

	static const read_fn read_fns[] = {
		&read_header,
		&read_alloc,
		&read_dealloc,
		&read_object
	};

	while ( keep_reading ) {

		if ((ret = read(read_fd, rec_type)) != sizeof(rec_type)) {

			if ( ret == -1 ) {
				fprintf(stderr, "Failed to read record type!\n");
			} else if ( ! ret ) {
				fprintf(stderr, "EOF\n");
			}
			
			return 1;
		}

		if (rec_type < 0 || rec_type >= ( sizeof(read_fns)/sizeof(read_fns[0]) ) ) {

			fprintf(stderr, "Error: Unknown record type %d. Looks like stream is corrupt!\n"
				"I'll dump what I have so far...\n", rec_type);

			return 2;
		} 

		if ( read_fns[rec_type]() ) {

			fprintf(stderr, "Record handler failed. %d\n", rec_type);
			return 3;
		}

		if ( ! (++records_consumed % 100000) ) {
			fprintf(stderr, "*** %llu records processed.\n");
		}
	}

	if ( ! keep_reading ) {
		
		fprintf(stderr, "Interrupted by signal. I'll dump what I have so far...\n");
	}
}


bool generate_callgrind_output_for_object_calls(FILE* file, Object* object,
	int* const visited_objects, int* const visited_symbols, int* const visited_sourcefiles, CallSite* call) {

	if (call->cum_alloc) {

		if ( ! visited_sourcefiles[call->source_file.id] ) {
			fprintf(file, "fl=(%lu) %s\n", call->source_file.id, call->source_file.name.c_str());
			visited_sourcefiles[call->source_file.id] = 1;
		} else {
			fprintf(file, "fl=(%lu)\n", call->source_file.id);
		}

		if ( ! visited_symbols[call->from_symbol.id] ) {
			fprintf(file, "fn=(%lu) %s\n", call->from_symbol.id, call->from_symbol.get_name());
			visited_symbols[call->from_symbol.id] = 1;
		} else {
			fprintf(file, "fn=(%lu)\n", call->from_symbol.id);
		}

		if (call->onward_calls.empty()) {

			// Leaf frame. Doesn't call anything else, so any cost must be 'self' cost.

			fprintf(file, "0x%llx %lu %llu\n\n", call->addr, call->line_no, call->cum_alloc);
		}

		BOOST_FOREACH(OnwardCall& oc, call->onward_calls) {

			CallSite* tc = oc.next;

			if (oc.cum_alloc) {

				if (&tc->from_symbol.object != object) {

					if ( ! visited_objects[tc->from_symbol.object.id] ) {
						fprintf(file, "cob=(%lu) %s\n", tc->from_symbol.object.id,
							tc->from_symbol.object.name.c_str());

						visited_objects[tc->from_symbol.object.id] = 1;
					} else {
						fprintf(file, "cob=(%lu)\n", tc->from_symbol.object.id);
					}
				}

				if (&tc->source_file != &call->source_file) {

					if ( ! visited_sourcefiles[tc->source_file.id] ) {
						fprintf(file, "cfl=(%lu) %s\n", tc->source_file.id, tc->source_file.name.c_str());
						visited_sourcefiles[tc->source_file.id] = 1;

					} else {
						fprintf(file, "cfl=(%lu)\n", tc->source_file.id);
					}
				}

				if ( ! visited_symbols[tc->from_symbol.id] ) {
					fprintf(file, "cfn=(%lu) %s\n", tc->from_symbol.id, tc->from_symbol.get_name());
					visited_symbols[tc->from_symbol.id] = 1;
				} else {
					fprintf(file, "cfn=(%lu)\n", tc->from_symbol.id);
				}

				fprintf(file, 
					"calls=%llu 0x%llx %lu\n"
					"0x%llx %lu %llu\n\n",
					oc.times_called, call->addr, call->line_no,
					tc->addr, tc->line_no, oc.cum_alloc
				);

			} // end-if (onward call has cost)

		} // end for-each (onward call)

	} // end-if (call-site has cost)

	return true;
}



int generate_callgrind_output (const std::string& file_name, const uint64_t starting_timestamp, const uint64_t ending_timestamp) {

	FILE* file = fopen(file_name.c_str(), "w+");

	// Header

	fprintf(file, 
		"version: 1\n"
		"creator: readalloc-0.1\n"
		"pid: %lu\n"
		"cmd: %s\n"
		"part: 1\n\n\n"
		"positions: instr line\n"
		"events: Bytes\n"
		"summary: %llu\n"
		"\n\n",
		remote_pid,
		remote_command.c_str(),
		active_alloc_total_cost
	);

	// All of this is for Callgrind name compression. We can't simply output the numerical 
	// aliases for all the objects, symbols, source files up-front because Kcachegrind gets confused.
	// Instead, we have to output the name along with the id the first time we encounter each
	// entity.

	const size_t total_entities = Object::get_next_id() + Symbol::get_next_id() + SourceFile::next_id;

	boost::scoped_array<int> visited_entities(new int[total_entities]);

	bzero(static_cast<void*>(visited_entities.get()), sizeof(int)*total_entities);

	int* const visited_objects = visited_entities.get();

	int* const visited_symbols = visited_entities.get() + Object::get_next_id();

	int* const visited_sourcefiles = visited_symbols + Symbol::get_next_id();


	BOOST_FOREACH(Object* object, known_objects) {

		if ( ! visited_objects[object->id] ) {
			fprintf(file, "ob=(%lu) %s\n", object->id, object->name.c_str());
			visited_objects[object->id] = 1;
		} else {
			fprintf(file, "ob=(%lu)\n", object->id);
		}

		object->visit_outward_calls(boost::bind(&generate_callgrind_output_for_object_calls, file, object, visited_objects, visited_symbols, visited_sourcefiles, _1));

	} // end for-each (known object)

	fprintf(file, "totals: %llu\n", active_alloc_total_cost);

	fclose(file);

	return 0;
}


void generate_callgrind_output_files(const uint32_t slice_interval_secs) {

	std::string base_callgrind_filename;

	if (remote_pid) {
		base_callgrind_filename = "callgrind.out." + remote_program + "." + boost::lexical_cast<std::string>(remote_pid);
	} else {
		base_callgrind_filename = "callgrind.out.unknown";
	}

	std::string callgrind_file = base_callgrind_filename;

	fprintf(stderr, "Number of active allocations: %llu, total cost: %llu, number of ELF objects: %lu\n",
		active_alloc_count, active_alloc_total_cost, known_objects.size());

	apply_alloc_costs(0, latest_alloc_timestamp+1);

	fprintf(stderr, "Generating full callgrind file: %s\n", callgrind_file.c_str());

	generate_callgrind_output(callgrind_file, 0, latest_alloc_timestamp+1);

	if (slice_interval_secs) {

		uint32_t slice_num = 0;

		for (uint64_t starting_timestamp = 0; starting_timestamp <= latest_alloc_timestamp;
			starting_timestamp += static_cast<uint64_t>(slice_interval_secs),++slice_num) {

			uint64_t ending_timestamp = starting_timestamp+static_cast<uint64_t>(slice_interval_secs);

			clear_all_alloc_costs();
			apply_alloc_costs(starting_timestamp, ending_timestamp);

			callgrind_file = base_callgrind_filename + "_slice_" +
				boost::lexical_cast<std::string>(slice_num) + "_" +
				boost::lexical_cast<std::string>(starting_timestamp) + "-" +
				boost::lexical_cast<std::string>(ending_timestamp);

			fprintf(stderr, "Generating slice callgrind file: %s\n", callgrind_file.c_str());

			generate_callgrind_output(callgrind_file, starting_timestamp, ending_timestamp);
		}
	}
}


int generate_unresolved_symbol_report (const std::string& file_name) {

	FILE* file = fopen(file_name.c_str(), "w+");

	//fprintf(stderr, "Objects:\n");
	BOOST_FOREACH(Object* object, known_objects) {

		//fprintf(stderr, "@0x%llx %s\n", object->base_vaddr,  object->name.c_str());

		BOOST_FOREACH(const uint64_t addr, object->get_unresolved_symbols()) {
			fprintf(file, "%s 0x%llx\n", object->name.c_str(), addr);
		}
	}

	fclose(file);

	return 0;
}


int generate_sample_file (const std::string& file_name, const std::vector<Sample>& samples, const uint32_t sample_interval_secs) {

	FILE* file = fopen(file_name.c_str(), "w+");

	fprintf(file, "# Runtime\tAlloc Count\tTotal Bytes\n");

	const Sample* prev_sample = &samples[0];

	BOOST_FOREACH(const Sample& sample, samples) {

		// We don't keep a sample entry for each interval, just the intervals that had some
		// activity. But when plotting a graph, we don't want sudden jumps, so fabricate the
		// missing intervals.
		uint64_t sample_time = prev_sample->sample_time;

		while (sample.sample_time-sample_time > sample_interval_secs) {
			fprintf(file, "%llu\t%llu\t%llu\n", sample_time, prev_sample->alloc_count, prev_sample->total_cost);

			sample_time += sample_interval_secs;
		}

		fprintf(file, "%llu\t%llu\t%llu\n", sample.sample_time, sample.alloc_count, sample.total_cost);

		prev_sample = &sample;
	}

	fclose(file);

	return 0;
}

void signal_handler(int sig) {

	keep_reading = false;
}

int init_bfd() {

	// Initialise libbfd for symbol lookup.
	bfd_init();

	fprintf(stderr, "Initialised bfd.\n");

	const char** target_list = bfd_target_list();

	size_t t=0;

	fprintf(stderr, "bfd supported targets: ");

	while (target_list[t]) {
		fprintf(stderr, "%s  ", target_list[t]);
		++t;
	}

	fprintf(stderr, "\n");

	free(target_list);

	return 0;
}

int main(int argc, const char* argv[]) {

	static const char* const copyright = 
		"readalloc Copyright (C) 2014 John Sadler\n"
		"This program comes with ABSOLUTELY NO WARRANTY\n"
		"This is free software, and you are welcome to redistribute it\n"
		"under certain conditions; see http://www.gnu.org/licenses/gpl.html for details.\n\n\n";

	fprintf(stderr, copyright);

	uint32_t time_slice_interval_secs = 0;

	po::options_description desc(
		"Options"
	);

	desc.add_options()
		("help", "show help message")
		("rootfs", "path to the rootfs of the device")
		("time-slice-interval-secs", po::value<uint32_t>(),
		"chop-up the total runtime into a number of slices and generate a separate "
		"callgrind file for each, detailing only the allocations made in that period")
		("sample-interval-secs", po::value<uint32_t>(),
		"sample the total active allocations periodically, and generate an output file "
		"suitable for plotting. Use this if you want to generate a historical view of "
		"allocations over time");

	po::variables_map vm;
	po::positional_options_description p;
	p.add("rootfs", -1);

	try {
		po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
		po::notify(vm);
	} catch (...) {
		std::cerr << desc << "\n";
		return 1;
	}

	if (vm.count("help")) {
		std::cerr << desc << "\n";
		return 1;
	}

	if ( ! vm.count("rootfs") ) {
		fprintf(stderr, "Must provide path to device rootfs.\n");
		return 1;
	} else {
		rootfs_dir = vm["rootfs"].as<std::string>();
	}

	if (vm.count("time-slice-interval-secs")) {
		time_slice_interval_secs = vm["time-slice-interval-secs"].as<uint32_t>();
	}

	if (vm.count("sample-interval-secs")) {
		sample_interval_secs = vm["sample-interval-secs"].as<uint32_t>();
		samples.push_back(Sample());
		samples.push_back(Sample());
	}

	fprintf(stderr, "Rootfs: %s\n", rootfs_dir.c_str());

	init_bfd();

	signal(SIGTERM, &signal_handler);
	signal(SIGINT, &signal_handler);

	fprintf(stderr, "Entering read loop...\n");

	start_reading();

	if (samples.size()) {

		samples.back().sample_time = latest_alloc_timestamp;

		std::string sample_file;
		if (remote_pid) {
			sample_file = remote_program + "." + boost::lexical_cast<std::string>(remote_pid) + ".samples";
		} else {
			sample_file = "unknown.samples";
		}

		generate_sample_file(sample_file, samples, sample_interval_secs);
	}

	generate_callgrind_output_files(time_slice_interval_secs);

	std::string unresolved_symbol_report_file;

	if (remote_pid) {
		unresolved_symbol_report_file = remote_program + "." + boost::lexical_cast<std::string>(remote_pid) + ".unresolved_symbols";
	} else {
		unresolved_symbol_report_file = "unknown.unresolved_symbols";
	}

	fprintf(stderr, "Generated unresolved symbols report: %s\n", unresolved_symbol_report_file.c_str());

	generate_unresolved_symbol_report(unresolved_symbol_report_file);

	return 0;
}


