# #!/bin/bash --login
target_source_name="${1}"
docker_repo_root='/opt/container.aflplusplus.template'
target_repo="${docker_repo_root}/TARGET_SRC/${target_source_name}"

bash --login -c "
  echo 'Welcome to the AFL++ Container...';
  echo 'Feel Free to Browse the Filesystem, Troubleshoot, etc.';
  echo 'Press CTRL+D to Begin Building the Instrumented Target';
  /bin/bash --login
"
# Define Target Instrumentation via instrumentation_globals.sh
source $docker_repo_root/TARGET/instrumentation_globals.sh

# THIS IS AN EXAMPLE OF HOW TO BUILD A TARGET FOLLOWING INSTRUMENTATION
cd $target_repo && CC=$preferred_afl CXX=$preferred_aflplusplus RANLIB=$preferred_afl_ranlib AR=$preferred_afl_ar NM=$preferred_alf_nm make clean
cd $target_repo && CC=$preferred_afl CXX=$preferred_aflplusplus RANLIB=$preferred_afl_ranlib AR=$preferred_afl_ar NM=$preferred_alf_nm ./buildconf --force
cd ${target_repo} && CC=$preferred_afl CXX=$preferred_aflplusplus RANLIB=$preferred_afl_ranlib AR=$preferred_afl_ar NM=$preferred_afl_nm ./configure
cd ${target_repo} && CC=$preferred_afl CXX=$preferred_aflplusplus RANLIB=$preferred_afl_ranlib AR=$preferred_afl_ar NM=$preferred_afl_nm make
cd ${target_repo} && make install

echo 'INFO: afl-fuzz will begin in 10 seconds'
for i in {1..10}; do
  printf '.'
  sleep 1
done
