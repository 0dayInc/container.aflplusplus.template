#!/bin/bash
# INSTRUMENTATION GLOBALS:
# FOR MORE DETAILS, SEE: https://aflplus.plus/docs/env_variables/

# --------------------------------------------------------------------------#
# Reserved for Specific ENV Settings Related to the Target Binary           #
# --------------------------------------------------------------------------#
export USE_ZEND_ALLOC=0
# --------------------------------------------------------------------------#

# --------------------------------------------------------------------------#
# ***LEAVE THESE VARIABLES ALONE - THEY'RE USED THROUGHOUT THIS PROJECT***  #
# --------------------------------------------------------------------------#
fuzz_session_root='/fuzz_session'
target_prefix="${fuzz_session_root}/TARGET"
preeny_root='/opt/preeny'
aflplusplus_source_root='/AFLplusplus'
container_afl_template_path='/opt/container.aflplusplus.template'
cflags='-ggdb'
cxxflags='-ggdb'
# --------------------------------------------------------------------------#

# --------------------------------------------------------------------------#
# AFL OPTIONS: TWEAK FOR YOUR SEPCIFIC TARGET                               #
# --------------------------------------------------------------------------#
# Set path of GNU linker
export LD=/usr/bin/ld

# Speed up fuzzing by forcing the linker to do
# all the work before the fork server kicks in
# export LD_BIND_NOW=1

# Define CC && CXX
# Use afl-clang-lto/afl-clang-lto++ 
# because it is faster and gives 
# better coverage than anything else 
# that is out there in the AFL world
export preferred_afl='afl-clang-lto'
export preferred_aflplusplus='afl-clang-lto++'
export preferred_afl_linker='afl-ld-lto'
export preferred_afl_ranlib='llvm-ranlib-14'
export preferred_afl_ar='llvm-ar-14'
export preferred_afl_nm='llvm-nm-14'
export preferred_llvm_config='llvm-config-14'

# We care about missing crashes...or do we?
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=0

# Will resume a fuzz run (same as providing -i -)
# for an existing out folder, even if a different
# -i was provided. Without this setting, afl-fuzz
# will refuse execution for a long-fuzzed out dir.
export AFL_AUTORESUME=1

# Causes the fuzzer to import test cases from other
# instances before doing anything else. This makes
# the “own finds” counter in the UI more accurate.
export AFL_IMPORT_FIRST=1

# Skips the check for CPU scaling policy. This is
# useful if you can’t change the defaults (e.g., no
# root access to the system) and are OK with some
# performance loss.
export AFL_SKIP_CPUFREQ=0

# Randomly reorders the input queue on startup.
# Requested by some users for unorthodox parallelized
# fuzzing setups, but not advisable otherwise.
export AFL_SHUFFLE_QUEUE=1

# Causes AFL++ to set LD_PRELOAD for the target
# binary without disrupting the afl-fuzz process
# itself. This is useful, among other things, for
# bootstrapping libdislocator.so
# ADDITIONALLY, HERE ARE PREENY OPTIONS FOR AFL_PRELOAD:
# crazyrealloc	ensures that whatever is being reallocated is always moved to a new location in memory, thus free()ing the old.
# dealarm	Disables alarm()
# defork	Disables fork()
# deptrace	Disables ptrace()
# derand	Disables rand() and random()
# desigact	Disables sigaction()
# desock	Channels socket communication to the console
# desock_dup	Channels socket communication to the console (simpler method)
# desrand	Does tricky things with srand() to control randomness.
# detime	Makes time() always return the same value.
# desleep	Makes sleep() and usleep() do nothing.
# deuid	Change the UID and effective UID of a process
# ensock	The opposite of desock -- like an LD_PRELOAD version of socat!
# eofkiller	Exit on EOF on several read functions
# getcanary	Dumps the canary on program startup (x86 and amd64 only at the moment).
# mallocwatch	When ltrace is inconvenient, mallocwatch provides info on heap operations.
# nowrite	Forces open() to open files in readonly mode. Downgrading from readwrite or writeonly mode, and taking care of append, mktemp and other write-related flags as well
# patch	Patches programs at load time.
# setcanary	Overwrites the canary with a user-provided one on program startup (amd64-only at the moment).
# setstdin	Sets user defined STDIN data instead of real one, overriding read, fread, fgetc, getc and getchar calls. Read here for more info
# startstop	Sends SIGSTOP to itself on startup, to suspend the process.
# writeout	Some binaries write() to fd 0, expecting it to be a two-way socket. This makes that work (by redirecting to fd 1).
# export AFL_PRELOAD="${aflplusplus_source_root}/libdislocator.so:${aflplusplus_source_root}/libcompcov.so:${preeny_root}/src/dealarm.so:${preeny_root}/src/defork.so:${preeny_root}/src/deptrace.so:${preeny_root}/src/derand.so:${preeny_root}/src/desigact.so:${preeny_root}/src/desleep.so:${preeny_root}/src/desock.so:${preeny_root}/src/desrand.so"
export AFL_PRELOAD="${aflplusplus_source_root}/libdislocator.so:${preeny_root}/src/dealarm.so::${preeny_root}/src/desigact.so:${preeny_root}/src/desleep.so"

# PREENY derand.so SPECIFIC SETTINGS:
export RAND=1337

# PREENY desrand.so SPECIFIC SETTINGS:
# # this sets the seed to 1337
export SEED=1337
# this sets the seed to such that the first "rand() % 128" will be 10
# export WANT=10 MOD=128
# finally, this makes the *third* "rand() % 128" be 10
# export SKIP=2 WANT=10 MOD=128

# Uses native trace-pc-guard instrumentation but additionally select
# options that are required to utilize the instrumentation for source
# code coverage.
# export AFL_LLVM_INSTRUMENT=1

# Produce a CmpLog binary.  CmpLog instrumentation
# enables logging of comparison operands in a shared
# memory. These values can be used by various mutators
# built on top of it.
export AFL_LLVM_CMPLOG=1

# Enables the CompareCoverage tracing of all cmp and
# sub in x86 and x86_64 and memory comparison functions
# export AFL_COMPCOV_LEVEL=2

# Causes afl-fuzz to terminate when all existing
# paths have been fuzzed and there were no new finds
# for a while. This would be normally indicated by
# the cycle counter in the UI turning green. May be
# convenient for some types of automated jobs.
export AFL_EXIT_WHEN_DONE=1

# Causes afl-fuzz to terminate if no new paths were
# found within a specified period of time (in seconds).
# May be convenient for some types of automated jobs.
# export AFL_EXIT_ON_TIME=0

# Enable the April 1st stats menu, set to -1 to
# disable although it is 1st of April.
# export AFL_PIZZA_MODE=1

# Helper application for afl-fuzz. It is a wrapper
# around GNU 'as', executed by the toolchain whenever
# using afl-gcc or afl-clang
export AFL_AS="${aflplusplus_source_root}/afl-as"

# Generate a dictionary in the target binary 
# based on string compare and memory compare 
# functions.  afl-fuzz will automatically get 
# these transmitted when starting to fuzz.  This 
# improves coverage on a lot of targets.
export AFL_LLVM_LTO_AUTODICTIONARY=1

# To speed up fuzzing, the shared memory map 
# is hard set to a specific address, by default 
# 0x10000. In most cases this will work without 
# any problems.  On unusual operating systems/
# processors/kernels or weird libraries this might 
# fail so to change the fixed address at compile 
# time set AFL_LLVM_MAP_ADDR with a better value 
# (a value of 0 or empty sets the map address to 
# be dynamic - the original afl way, which is slower).
# AFL_LLVM_MAP_DYNAMIC can be set so the shared
# memory address is dynamic (which is safer but also
# slower).
#export AFL_LLVM_MAP_DYNAMIC=1

# There is also an advanced mode which instruments 
# loops in a way so that afl-fuzz can see which loop 
# path has been selected but not being able to see how 
# often the loop has been rerun.  This again is a 
# tradeoff for speed for less path information.
#export AFL_LLVM_INSTRIM_LOOPHEAD=1

# This great feature will split compares into series of
# single byte comparisons to allow afl-fuzz to find 
# otherwise rather impossible paths. It is not restricted
# to Intel CPUs.
export AFL_LLVM_LAF_TRANSFORM_COMPARES=1
export AFL_LLVM_LAF_SPLIT_COMPARES=1
export AFL_LLVM_LAF_SPLIT_SWITCHES=1
export AFL_LLVM_LAF_SPLIT_FLOATS=1
export AFL_LLVM_LAF_ALL=1
#export AFL_HARDEN=1

# Use Custom Mutators :)
custom_mutators_root="${aflplusplus_source_root}/custom_mutators"
aflpp_so="${custom_mutators_root}/aflpp/aflpp-mutator.so"
aflpp_tritondse_so="${custom_mutators_root}/aflpp/aflpp-tritondse-mutator.so"
atnwalk_so="${custom_mutators_root}/atnwalk/atnwalk.so"
autotokens_so="${custom_mutators_root}/autotokens/autotokens.so"
gramatron_so="${custom_mutators_root}/gramatron/gramatron.so"
grammar_mutator_so="${custom_mutators_root}/grammar_mutator/grammar-mutator.so"
honggfuzz_so="${custom_mutators_root}/honggfuzz/honggfuzz-mutator.so"
libafl_base_so="${custom_mutators_root}/libafl_base/libafl_base.so"
libfuzzer_so="${custom_mutators_root}/libfuzzer/libfuzzer-mutator.so"
radamsa_so="${custom_mutators_root}/radamsa/radamsa-mutator.so"
symcc_so="${custom_mutators_root}/symcc/symcc-mutator.so"
symqemu_so="${custom_mutators_root}/symqemu/symqemu-mutator.so"

# These entries can be used together.  
# export AFL_CUSTOM_MUTATOR_LIBRARY="${gramatron_so};${honggfuzz_so};${libfuzzer_so};${radamsa_so}"
export AFL_CUSTOM_MUTATOR_LIBRARY="${honggfuzz_so};${libfuzzer_so};${radamsa_so}"

# CUSTOM MUTATOR-SPECIFIC ENVS
# export GRAMATRON_AUTOMATION="${aflplusplus_source_root}/custom_mutators/gramatron/grammars/php/source_automata.json"

# Custom mutators not mentioned above in the AFL_CUSTOM_MUTATOR_LIBRARY
# are used independently.  For example, to use the libafl_base mutator:
# export AFL_CUSTOM_MUTATOR_ONLY=1
# export AFL_CUSTOM_MUTATOR_LIBRARY="${libafl_base_so}"

# DEBUG
export AFL_DEBUG=0
export AFL_DEBUG_CHILD=0

# IN CASE THERE'S CTORS AND REQUIRES A HUGE COVERAGE MAP
# export AFL_MAP_SIZE=10000000
# --------------------------------------------------------------------------#

# --------------------------------------------------------------------------#
# USE these during make only
# Activates the address sanitizer (memory corruption detection)
# AFL_USE_ASAN=1
# ASAN_OPTIONS=help=1,verbosity=3,detect_leaks=1,abort_on_error=1,symbolize=0,check_initialization_order=true,detect_stack_use_after_return=true,strict_string_checks=true,detect_invalid_pointer_pairs=2,malloc_context_size=0,allocator_may_return_null=1

# Activates the Control Flow Integrity sanitizer
# (e.g. type confusion vulnerabilities)
# AFL_USE_CFISAN=1
# CFISAN_OPTIONS=help=1

# Activates the leak sanitizer. To perform a leak check
# within your program at a certain point (such as at the
# end of an __AFL_LOOP()), you can run the macro __AFL_LEAK_CHECK();
# which will cause an abort if any memory is leaked (you can combine
# this with the __AFL_LSAN_OFF(); and __AFL_LSAN_ON(); macros to
# avoid checking for memory leaks from memory allocated between these
# two calls.
# AFL_USE_LSAN=1
# LSAN_OPTIONS=help=1,exit_deo=23,fast_unwind_on_malloc=0,symbolize=0,print_suppressions=0,detect_leaks=1,use_stacks=0,use_registers=0,use_globals=0,use_tls=0,verbosity=1

# Use Memory Sanitizer
# AFL_USE_MSAN=1
# MSAN_OPTIONS=help=1,exit_code=86,abort_on_error=1,symbolize=0,msan_track_origins=0,allocator_may_return_null=1

# Activates the thread sanitizer to find thread race conditions
# AFL_USE_TSAN=1
# TSAN_OPTIONS=help=1

# Use Unexpected Behavior Sanitizer
# AFL_USE_UBSAN=1
# UBSAN_OPTIONS=help=1
