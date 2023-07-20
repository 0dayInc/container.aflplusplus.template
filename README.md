```
$ git clone https://github.com/0dayInc/container.aflplusplus.template
$ cd container.aflplusplus.template
$ ./AFLplusplus_template.sh -h
```

Example Usage:
```
$ ./AFLplusplus_template.sh -T "target_bin --flags" -m main
```

To add another CPU core into the fuzzing mix, open a new terminal window:
```
$ ./AFLplusplus_template.sh -T "target_bin --flags" -m secondary
```

To add your own test cases, place them in ./TARGET/test_cases and they'll be copied into /fuzz_session/AFLplusplus/input.

Happy Fuzzing!
