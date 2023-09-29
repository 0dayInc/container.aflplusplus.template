### **Intro** ###
#### **What** ####
This project aims to guide security researchers along the journey of squeezing out as much capability of AFL++ as possible for any engagement where fuzzing is desired.

#### **Why** ####
To paraphrase what a wise meme on the Internet once said...<br/>
![WiseMeme](https://raw.githubusercontent.com/0dayInc/container.aflplusplus.template/master/documentation/one_does_not_simply_install_afl%2B%2B.jpeg)

#### **How** ####
This project accomplishes this goal by:
- Leveraging a good balance of AFL++'s advanced capbilities, including those that further advance AFL++'s advanced capbilities :) Examples include:
    - [Preeny](https://github.com/zardus/preeny)
    - [LibFuzzer](https://llvm.org/docs/LibFuzzer.html)
    - [HonggFuzz](https://github.com/google/honggfuzz)
    - [Radamsa](https://gitlab.com/akihe/radamsa)
    - [Address Sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
    - And Much More...Checkout [instrumentation_globals.sh](https://github.com/0dayInc/container.aflplusplus.template/blob/master/TARGET/instrumentation_globals.sh) && [init_aflplusplus_container.sh](https://github.com/0dayInc/container.aflplusplus.template/blob/master/TARGET/init_aflplusplus_container.sh) for more details.
- Providing guidance around instrumenting binaries with AFL++ "Persistence Mode" with functions such as `__AFL_FUZZ_INIT()`, `__AFL_INIT()`, && `__AFL_LOOP()`
- Supports the ability to spin up a "main" fuzzer with multiple "secondaries"
- Enabling the Creation of test cases for a given target
- Cranking out as many mutations / second as possible
- Aiding researchers in discovering .so files loaded via dlopen (which can be appended to AFL_PRELOAD at runtime)

#### **Installation / Usage** ####
1. Clone the repo:
```
$ cd /opt
$ sudo git clone https://github.com/0dayInc/container.aflplusplus.template
$ sudo chown -R $USER:$USER container.aflplusplus.template
```

2. Review Usage:
```
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

```

3. Clone the Target Source Code Repo:
```
$ cd TARGET_SRC
$ git clone <TARGET_GIT_REPO>
```

4. Instrument your target function(s) w/ `__AFL_INIT` &&`__AFL_LOOP`:
```
$ vi <TARGET_GIT_REPO>/<TARGET_SRC_FILE_TO_INSTRUMENT_W __AFL_INIT && __AFL_LOOP>
```

5. Sanity check instrumentation_globals.sh && build_target.sh scripts
```
$ cd ..
$ vi TARGET/instrumentation_globals.sh
$ vi TARGET/build_target.sh
```

6. Add your own test cases as single files in the `./TARGET/test_cases` directory.  From there, they'll be copied into /fuzz_session/AFLplusplus/input once fuzzing begins.

7. Begin Fuzzing (Example Usage):
```
$ tmux new -s afl_main
$ ./AFLplusplus_template.sh \
  -m main \
  -r <src_folder_name> \
  -T "target_bin --flags"
```

8. add another CPU core into the fuzzing mix:
```
$ tmux new -s afl_sec1
$ ./AFLplusplus_template.sh \
  -m secondary \
  -r <src_folder_name> \
  -T "target_bin --flags"
```


Happy Fuzzing!

### **Keep Us Caffeinated** ###
If you've found this project useful and you're interested in supporting our efforts, we invite you to take a brief moment to keep us caffeinated:

[![Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoff.ee/0dayinc)


### [**0x004D65726368**](https://0day.myspreadshop.com/) ###

[![PWN Sticker](https://image.spreadshirtmedia.com/image-server/v1/products/T1459A839PA3861PT28D1044068794FS8193/views/1,width=300,height=300,appearanceId=839,backgroundColor=000000/ultimate-hacker-t-shirt-to-convey-to-the-public-a-hackers-favorite-past-time.jpg)](https://0day.myspreadshop.com/stickers)

[![Coffee Mug](https://image.spreadshirtmedia.com/image-server/v1/products/T1313A1PA3933PT10X2Y25D1020472680FS6327/views/3,width=300,height=300,appearanceId=1,backgroundColor=000000/https0dayinccom.jpg)](https://0day.myspreadshop.com/accessories+mugs+%26+drinkware)

[![Mouse Pad](https://image.spreadshirtmedia.com/image-server/v1/products/T993A1PA2168PT10X162Y26D1044068794S100/views/1,width=300,height=300,appearanceId=1,backgroundColor=000000/ultimate-hacker-t-shirt-to-convey-to-the-public-a-hackers-favorite-past-time.jpg)](https://0day.myspreadshop.com/accessories)

[![0day Inc.](https://image.spreadshirtmedia.com/image-server/v1/products/T951A550PA3076PT17X0Y73D1020472680FS8515/views/1,width=300,height=300,appearanceId=70,backgroundColor=000000/https0dayinccom.jpg)](https://shop.spreadshirt.com/0day/0dayinc-A5c3e498cf937643162a01b5f?productType=951&appearance=70)

[![Black Fingerprint Hoodie](https://image.spreadshirtmedia.com/image-server/v1/products/T111A2PA3208PT17X169Y51D1020472728FS6268/views/1,width=300,height=300,appearanceId=2/https0dayinccom.jpg)](https://shop.spreadshirt.com/0day/blackfingerprint-A5c3e49db1cbf3a0b9596b4d0?productType=111&appearance=2)
