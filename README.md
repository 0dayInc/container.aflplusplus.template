### **Intro** ###
#### **What** ####
This project aims to guide security researchers along the journey in squeezing out as much capability of AFL++ as possible for any engagement in which a researcher is fuzzing a target.

#### **Why** ####
It's one thing to install AFL++ and "start fuzzing."  It's quite another to install AFL++ and "fuzz effectively"


#### **How** ####
The environment project aims to:
- Avoid thashing hard drives (which is why fuzzing happens within memory for this project, i.e. the tmpfs /fuzz_session)
- Provide guidance around instrumenting binaries leveraging the __AFL_LOOP function
- Has the ability to spin up a "main" fuzzer with multiple "secondaries"
- Enabling the Creation of test cases for a given target
- Cranking out as many mutations / second as possible

#### **Installation / Usage** ####
```
$ git clone https://github.com/0dayInc/container.aflplusplus.template
$ cd container.aflplusplus.template
$ ./AFLplusplus_template.sh -h
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
