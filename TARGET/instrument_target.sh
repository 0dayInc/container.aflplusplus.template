# #!/bin/bash --login
target_source_name="${1}"
container_afl_template_path='/opt/container.aflplusplus.template'
instrumentation_globals="${container_afl_template_path}/TARGET/instrumentation_globals.sh"
source $instrumentation_globals
target_repo="${container_afl_template_path}/TARGET_SRC/${target_source_name}"

# Provide an opportunity to troubleshoot the container
cd / && bash --login -c "
  printf '\n\n\n';
  echo '#--------------------------------------------------------#';
  echo '| Welcome to the AFL++ Container...                      |';
  echo '| Feel Free to Browse the Filesystem, Troubleshoot, etc. |';
  echo '| Press CTRL+D to Begin Building the Instrumented Target |';
  echo '#--------------------------------------------------------#';
  /bin/bash --login
"

# THIS IS AN EXAMPLE OF HOW TO BUILD A TARGET FOLLOWING INSTRUMENTATION
# Variables not declared in this script are declared in instrumentation_globals
# and are sourced via /etc/bash.bashrc in the Docker container.
cd $target_repo && CC=$preferred_afl CXX=$preferred_aflplusplus RANLIB=$preferred_afl_ranlib AR=$preferred_afl_ar NM=$preferred_alf_nm make clean
cd $target_repo && CC=$preferred_afl CXX=$preferred_aflplusplus RANLIB=$preferred_afl_ranlib AR=$preferred_afl_ar NM=$preferred_alf_nm ./buildconf --force
cd ${target_repo} && CC=$preferred_afl CXX=$preferred_aflplusplus RANLIB=$preferred_afl_ranlib AR=$preferred_afl_ar NM=$preferred_afl_nm ./configure
cd ${target_repo} && CC=$preferred_afl CXX=$preferred_aflplusplus RANLIB=$preferred_afl_ranlib AR=$preferred_afl_ar NM=$preferred_afl_nm make
cd ${target_repo} && make install

printf "\nINFO: afl-fuzz will begin in 10 seconds"
for i in {1..10}; do
  printf '.'
  sleep 1
done
printf "\n"
