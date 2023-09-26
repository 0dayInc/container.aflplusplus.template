# #!/bin/bash --login
target_source_name="${1}"
append_to_afl_preload="${2}"
container_afl_template_path='/opt/container.aflplusplus.template'
instrumentation_globals="${container_afl_template_path}/TARGET/instrumentation_globals.sh"
cd / && source $instrumentation_globals
target_repo="${container_afl_template_path}/TARGET_SRC/${target_source_name}"

if [[ $append_to_afl_preload != '' ]]; then
  export AFL_PRELOAD="${AFL_PRELOAD}:${append_to_afl_preload}"
else
  grep -Rn \
    -e 'dlopen(' \
    $target_repo \
    2> /dev/null | \
    grep -E '^.*\.so.*'

  if (( $? == 0 )); then
    printf '\n\n\n';
    echo '#--------------------------------------------------------#'
    echo '| WARN: No TARGET-SPECIFIC .so files are referenced in   |'
    echo '| AFL_PRELOAD but these .so files are loaded by dlopen() |'
    echo '#--------------------------------------------------------#'
    printf '\n\n\n';
    grep -Rn \
      -e 'dlopen(' \
      $target_repo \
      2> /dev/null | \
      grep -E '^.*\.so.*'

    # Found .so files
    # Read in user's CTRL+C to quit or enter to continue
    printf '\n\n\n';
    # read -p 'Press Enter to PROCEED || any other key to EXIT...' -n 1 -r -s choice
    # case $choice in 
    #   '') echo 'instrumenting.';;
    #   *) echo 'goodbye.'; exit 0;;
    # esac
  fi
fi

# Provide an opportunity to troubleshoot the container
# bash --login -c "
#   printf '\n\n\n';
#   echo '#--------------------------------------------------------#';
#   echo '| Welcome to the AFL++ Container...                      |';
#   echo '| Feel Free to Browse the Filesystem, Troubleshoot, etc. |';
#   echo '| Press CTRL+D to Begin Building the Instrumented Target |';
#   echo '#--------------------------------------------------------#';
#   /bin/bash --login
# "

# THIS IS AN EXAMPLE OF HOW TO BUILD A TARGET FOLLOWING INSTRUMENTATION
# Variables not declared in this script are declared in instrumentation_globals
# and are sourced via /etc/bash.bashrc in the Docker container.
#

# Target-Specific Dependencies to be installed via apt
apt install -y \
  autoconf \
  libgmp-dev \
  gperf \
  libffi-dev \
  libyaml-dev \
  openssl \
  zlib1g-dev

# Build the Target's configure script
if [[ -f $target_repo/autogen.sh ]]; then
  cd $target_repo && CFLAGS=$cflags \
                     CXXFLAGS=$cxxflags \
                     CC=$preferred_afl \
                     CXX=$preferred_aflplusplus \
                     RANLIB=$preferred_afl_ranlib \
                     AR=$preferred_afl_ar \
                     NM=$preferred_alf_nm \
                     ./autogen.sh
fi


if [[ ! -d $target_repo/build ]]; then
  mkdir -p $target_repo/build
fi

if [[ ! -d ~/.rubies ]]; then
  mkdir ~/.rubies
fi

# Execute the Target's configure script
if [[ -f $target_repo/configure ]]; then
  cd ${target_repo}/build && CFLAGS=$cflags \
                       CXXFLAGS=$cxxflags \
                       CC=$preferred_afl \
                       CXX=$preferred_aflplusplus \
                       RANLIB=$preferred_afl_ranlib \
                       AR=$preferred_afl_ar \
                       NM=$preferred_afl_nm \
                       ../configure \
                         --disable-shared \
                         --disable-install-doc \
                         --prefix=$HOME/.rubies/ruby-master
fi

# Clean up Previous Build, Build Again, && Install the Target
if [[ -f $target_repo/Makefile ]]; then
  cd ${target_repo} && CFLAGS=$cflags \
                       CXXFLAGS=$cxxflags \
                       CC=$preferred_afl \
                       CXX=$preferred_aflplusplus \
                       RANLIB=$preferred_afl_ranlib \
                       AR=$preferred_afl_ar \
                       NM=$preferred_afl_nm \
                       AFL_USE_ASAN=1 \
                       AFL_USE_CIFSAN=1 \
                       AFL_USE_UBSAN=1 \
                       AFL_USE_LSAN=1 \
                       make clean && \
                       make && \
                       make install
fi

printf "\nINSTRUMENTATION COMPLETE: afl-fuzz will begin in 10 seconds"
for i in {1..10}; do
  printf '.'
  sleep 1
done
printf "\n"
