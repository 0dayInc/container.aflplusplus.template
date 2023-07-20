# #!/bin/bash --login
other_repos_root='/opt'
docker_repo_root="${other_repos_root}/container.aflplusplus.wrapper"

fuzz_session_root='/fuzz_session'
afl_session_root="${fuzz_session_root}/AFLplusplus"
afl_input="${afl_session_root}/input"
afl_output="${afl_session_root}/multi_sync"

target_repo="${fuzz_session_root}/TARGET_SRC"
target_prefix="${fuzz_session_root}/TARGET"

# Define Target Instrumentation via instrumentation_globals.sh
source $docker_repo_root/TARGET/instrumentation_globals.sh
# THIS IS AN EXAMPLE OF HOW TO INSTRUMENT A TARGET
#
# YOU'LL NEED TO MODIFY THIS TO SUIT YOUR TARGET
if [[ -d $target_repo ]]; then
  rm -rf $target_repo
fi

cd $target_repo && CC=$preferred_afl CXX=$preferred_aflplusplus RANLIB=$preferred_afl_ranlib AR=$preferred_afl_ar NM=$preferred_alf_nm ./buildconf
cd ${target_repo} && CC=$preferred_afl CXX=$preferred_aflplusplus RANLIB=$preferred_afl_ranlib AR=$preferred_afl_ar NM=$preferred_afl_nm ./configure --prefix=$target_prefix
cd ${target_repo} && CC=$preferred_afl CXX=$preferred_aflplusplus RANLIB=$preferred_afl_ranlib AR=$preferred_afl_ar NM=$preferred_afl_nm make
cd ${target_repo} && make install
