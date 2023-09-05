# #!/bin/bash --login
target_source_name="${1}"
append_to_afl_preload="${2}"
container_afl_template_path='/opt/container.aflplusplus.template'
instrumentation_globals="${container_afl_template_path}/TARGET/instrumentation_globals.sh"
source $instrumentation_globals
target_repo="${container_afl_template_path}/TARGET_SRC/${target_source_name}"

if [[ $append_to_afl_preload != '' ]]; then
  export AFL_PRELOAD="${AFL_PRELOAD}:${append_to_afl_preload}"
fi

# Provide an opportunity to troubleshoot the container
cd / 
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
