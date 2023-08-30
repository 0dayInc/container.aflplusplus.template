#!/bin/bash --login
# INSTRUMENTATION GLOBALS:
# FOR MORE DETAILS, SEE: https://aflplus.plus/docs/env_variables/

custom_mutators_root='/AFLplusplus/custom_mutators'
radamsa_mutator="${custom_mutators_root}/radamsa/radamsa-mutator.so"
honggfuzz_mutator="${custom_mutators_root}/honggfuzz/honggfuzz.so"

# Set path of GNU linker
export LD=/usr/bin/ld

# Speed up fuzzing by forcing the linker to do
# all the work before the fork server kicks in
export LD_BIND_NOW=1

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
export AFL_PRELOAD=1

# Causes afl-fuzz to terminate when all existing
# paths have been fuzzed and there were no new finds
# for a while. This would be normally indicated by
# the cycle counter in the UI turning green. May be
# convenient for some types of automated jobs.
export AFL_EXIT_WHEN_DONE=0

# Enable the April 1st stats menu, set to -1 to
# disable although it is 1st of April.
export AFL_PIZZA_MODE=1

# Helper application for afl-fuzz. It is a wrapper
# around GNU 'as', executed by the toolchain whenever
# using afl-gcc or afl-clang
export AFL_AS='/AFLplusplus/afl-as'

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

# Activates the address sanitizer (memory corruption detection)
export AFL_USE_ASAN=1
export ASAN_OPTIONS=verbosity=3,detect_leaks=0,abort_on_error=1,symbolize=0,check_initialization_order=true,detect_stack_use_after_return=true,strict_string_checks=true,detect_invalid_pointer_pairs=2,malloc_context_size=0,allocator_may_return_null=1

# Activates the Control Flow Integrity sanitizer
# (e.g. type confusion vulnerabilities)
export AFL_USE_CFISAN=1

# Activates the leak sanitizer. To perform a leak check
# within your program at a certain point (such as at the
# end of an __AFL_LOOP()), you can run the macro __AFL_LEAK_CHECK();
# which will cause an abort if any memory is leaked (you can combine
# this with the __AFL_LSAN_OFF(); and __AFL_LSAN_ON(); macros to
# avoid checking for memory leaks from memory allocated between these
# two calls.
# export AFL_USE_LSAN=1
# export LSAN_OPTIONS=exit_deo=23,fast_unwind_on_malloc=0,symbolize=0,print_suppressions=0,detect_leaks=1,use_stacks=0,use_registers=0,use_globals=0,use_tls=0,verbosity=1

# Use Memory Sanitizer
# export AFL_USE_MSAN=1
# export MSAN_OPTIONS=exit_code=86,abort_on_error=1,symbolize=0,msan_track_origins=0,allocator_may_return_null=1

# Activates the thread sanitizer to find thread race conditions
# export AFL_USE_TSAN=1

# Use Unexpected Behavior Sanitizer
export AFL_USE_UBSAN=1

# Use Custom Mutators :)
export AFL_CUSTOM_MUTATOR_LIBRARY=$radamsa_mutator:$honggfuzz_mutator

# DEBUG
export AFL_DEBUG=0
export AFL_DEBUG_CHILD=0
