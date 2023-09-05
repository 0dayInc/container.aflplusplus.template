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
  echo 'INFO: No AFL_PRELOAD variable was provided'
  echo 'AFL_PRELOAD .so Files for Consideration:'
  grep -R 'dlopen(' $target_repo 2> /dev/null | grep -E '^.*\.so"'
  if (( $(echo $?) == 0 )); then
    # Found .so files
    # Read in user's CTRL+C to quit or enter to continue
    read -p 'Pressing Enter to proceed || any key to exit...' -n 1 -r -s choice
    case $choice in 
      '') echo 'INFO: Instrumenting...';;
      *) echo 'INFO: Goodbye.'; exit 0;;
    esac
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
  bison \
  build-essential \
  libsqlite3-dev \
  libxml2-dev \
  pkg-config \
  re2c

# Clean up any previous builds
cd $target_repo && CFLAGS=$cflags \
                   CXXFLAGS=$cxxflags \
                   CC=$preferred_afl \
                   CXX=$preferred_aflplusplus \
                   RANLIB=$preferred_afl_ranlib \
                   AR=$preferred_afl_ar \
                   NM=$preferred_alf_nm \
                   make clean

# Build the target's configure script
cd $target_repo && CFLAGS=$cflags \
                   CXXFLAGS=$cxxflags \
                   CC=$preferred_afl \
                   CXX=$preferred_aflplusplus \
                   RANLIB=$preferred_afl_ranlib \
                   AR=$preferred_afl_ar \
                   NM=$preferred_alf_nm \
                   ./buildconf --force

# Execute the target's configure script
cd ${target_repo} && CFLAGS=$cflags \
                     CXXFLAGS=$cxxflags \
                     CC=$preferred_afl \
                     CXX=$preferred_aflplusplus \
                     RANLIB=$preferred_afl_ranlib \
                     AR=$preferred_afl_ar \
                     NM=$preferred_afl_nm \
                     ./configure --disable-shared

# Build the target
cd ${target_repo} && CFLAGS=$cflags \
                     CXXFLAGS=$cxxflags \
                     CC=$preferred_afl \
                     CXX=$preferred_aflplusplus \
                     RANLIB=$preferred_afl_ranlib \
                     AR=$preferred_afl_ar \
                     NM=$preferred_afl_nm \
                     make

# Install the target
cd ${target_repo} && make install

printf "\nINFO: afl-fuzz will begin in 10 seconds"
for i in {1..10}; do
  printf '.'
  sleep 1
done
printf "\n"
