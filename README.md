### **Intro** ###
#### **What** ####
This project aims to guide security researchers along the journey of squeezing out as much capability of AFL++ as possible for any engagement where fuzzing is desired.

#### **Why** ####
To paraphrase a wise meme on the Internet...<br/>

"One does not simply install AFL++ and fuzz for 0days."

#### **How** ####
The environment project aims to:
- Leverage a good balance of AFL++'s advanced capbilities, including those that further advances AFL++'s capbilities.  Examples include:
    - [Preeny](https://github.com/zardus/preeny)
    - [LibFuzzer](https://llvm.org/docs/LibFuzzer.html)
    - [HonggFuzz](https://github.com/google/honggfuzz)
    - [Radamsa](https://gitlab.com/akihe/radamsa)
    - [Address Sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
    - And Much More...Checkout [instrumentation_globals.sh](https://github.com/0dayInc/container.aflplusplus.template/blob/master/TARGET/instrumentation_globals.sh) && [init_aflplusplus_container.sh](https://github.com/0dayInc/container.aflplusplus.template/blob/master/TARGET/init_aflplusplus_container.sh) for more details.
- Provide guidance around instrumenting binaries leveraging AFL++ macros such as __AFL_INIT() && __AFL_LOOP();
- Has the ability to spin up a "main" fuzzer with multiple "secondaries"
- Enabling the Creation of test cases for a given target
- Crank out as many mutations / second as possible
- Aid resercher in finding .so files loaded via dlopen (to be passed into AFL_PRELOAD)

#### **Installation / Usage** ####
```
$ git clone https://github.com/0dayInc/container.aflplusplus.template
$ cd container.aflplusplus.template
$ ./AFLplusplus_template.sh -h
USAGE:
./AFLplusplus_template.sh
    -h                     # Display USAGE

    -T <TARGET CMD/FLAGS>  # REQUIRED
                           # TARGET CMD / FLAGS of the target binary
                           # to be fuzzed. It must reside in the
                           # TARGET prefix (i.e. /fuzz_session/TARGET)

    -m <main || secondary> # REQUIRED
                           # afl++ Mode 

    -r <src dir name>      # REQUIRED
                           # Name of the source code folder
                           # residing in ./TARGET_SRC to build

    -P                     # OPTIONAL / main MODE ONLY
                           # Preload target specific, colon delimited
                           # list of .so files to append to AFL_PRELOAD

    -c                     # OPTIONAL / main MODE ONLY
                           # Nuke contents of TARGET prefix
                           # (i.e. /fuzz_session/TARGET)
                           # which is tmpfs and LOST AFTER REBOOT
                           # OF HOST OS

    -n                     # OPTIONAL / main MODE ONLY
                           # Nuke contents of multi-sync (New afl++ Session)
                           # (i.e. /fuzz_session/AFLplusplus/multi_sync)
                           # which is tmpfs and LOST AFTER REBOOT
                           # OF HOST OS

    -t                     # OPTIONAL / main MODE ONLY
                           # Nuke contents of input (afl++ Test Cases)
                           # (i.e. /fuzz_session/AFLplusplus/input)
                           # which is tmpfs and LOST AFTER REBOOT
                           # OF HOST OS

    -D                     # OPTIONAL
                           # Enable Debugging

$ cd TARGET_SRC
$ git clone <TARGET_GIT_REPO>
$ vi <TARGET_GIT_REPO>/<SRC_FILE_TO_INSTRUMENT_W __AFL_INIT && __AFL_LOOP>
```

Example Usage:
```
$ ./AFLplusplus_template.sh -r <src_folder_name> -T "target_bin --flags" -m main
```

To add another CPU core into the fuzzing mix, open a new terminal window:
```
$ ./AFLplusplus_template.sh -r <src_folder_name> -T "target_bin --flags" -m secondary
```

To add your own test cases, place them in ./TARGET/test_cases and they'll be copied into /fuzz_session/AFLplusplus/input.

Happy Fuzzing!
