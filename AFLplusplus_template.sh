#!/bin/bash --login
usage() {
  echo 'USAGE:'
  echo "${0}
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
  "
  exit 1
}

no_args='true'
afl_mode=''
target_source_name=''
nuke_target_prefix='false'
nuke_multi_sync='false'
nuke_test_cases='false'
debug='false'

while getopts "hT:m:r:cntLD" flag; do
  case $flag in
    'h') usage;;
    'T') target_name="${OPTARG}";;
    'm') afl_mode="${OPTARG}";;
    'r') target_source_name="${OPTARG}";;
    'c') nuke_target_prefix='true';;
    'n') nuke_multi_sync='true';;
    't') nuke_test_cases='true';;
    'D') debug='true';;
    *) usage;;
  esac
  no_args='false'
done

# If no args are passed, then return usage
if [[ $no_args == 'true' ]]; then
  echo 'ERROR: Missing Required Args'
  usage
fi

if [[ $target_source_name == '' ]]; then
  echo 'ERROR: -r Flag is Required'
  echo $target_source_name
  usage
fi

if [[ $afl_mode != 'main' ]]; then
  if [[ $nuke_target_prefix != 'false' || $nuke_multi_sync != 'false' ]]; then
    echo 'ERROR: -c || -n Flags Can Only be Used with "-m main"'
    usage
  fi
fi

this_repo_root=$(pwd)
this_repo_name=`basename ${this_repo_root}`
docker_repo_root="/opt/${this_repo_name}"

fuzz_session_root='/fuzz_session'
target_test_cases="${this_repo_root}/TARGET/test_cases"

afl_session_root="${fuzz_session_root}/AFLplusplus"
afl_input="${afl_session_root}/input"
afl_output="${afl_session_root}/multi_sync"

target_prefix="${fuzz_session_root}/TARGET"

# Ensure folder conventions are intact
if [[ ! -d $fuzz_session_root ]]; then
  sudo mkdir $fuzz_session_root
  sudo chmod 777 $fuzz_session_root 
  sudo mount \
    -t tmpfs \
    -o exec,nosuid,nodev,noatime,mode=1777,size=8G \
    tmpfs \
    $fuzz_session_root
fi

if [[ ! -d $afl_session_root ]]; then
  mkdir $afl_session_root
  sudo chmod 777 $afl_session_root
fi

if [[ ! -d $afl_input ]]; then
  mkdir $afl_input
  sudo chmod 777 $afl_input
fi

if [[ ! -d $afl_output ]]; then
  mkdir $afl_output
  sudo chmod 777 $afl_output
fi

this_session_rand=$RANDOM

# Set ADL Mode
if [[ $afl_mode == 'main' ]]; then
  afl_mode_selection="-M MAIN"
else
  afl_mode_selection="-S SEC${this_session_rand}"
fi

# Initialize Fuzz Session
# TODO: Figure out what values were before so 
# they can be reversed when fuzz session is complete
fuzz_session_init='
  echo core > /proc/sys/kernel/core_pattern &&
  echo never > /sys/kernel/mm/transparent_hugepage/enabled &&
  echo 1 >/proc/sys/kernel/sched_child_runs_first &&
  echo 1 >/proc/sys/kernel/sched_autogroup_enabled &&
  source /opt/container.aflplusplus.template/TARGET/instrumentation_globals.sh &&
'

if [[ $debug == 'true' ]]; then
  fuzz_session_init="
    ${fuzz_session_init} &&
    export AFL_DEBUG=1 &&
    export AFL_DEBUG_CHILD=1 &&
  "
fi

fuzz_session_init="
  ${fuzz_session_init}
  afl-fuzz \
    ${afl_mode_selection} \
    -T AFLplusplus \
    -i ${afl_session_root}/input \
    -o ${afl_session_root}/multi_sync \
    -m none \
    -t 6000+ \
    -D \
    -- ${target_name}
"

case $afl_mode in
  'main')
    # Nuke contents of TARGET Prefix
    # if -c was passed as arg
    if [[ -d $target_prefix && $nuke_target_prefix == 'true' ]]; then
      sudo rm -rf $target_prefix
    fi

    # Nuke contents of multi-sync (New afl++ Session)
    # if -n was passed as arg
    if [[ -d $afl_input && $nuke_test_cases == 'true' ]]; then
      sudo rm -rf $afl_input/*
    fi

    # Nuke contents of multi-sync (New afl++ Session)
    # if -n was passed as arg
    if [[ -d $afl_output && $nuke_multi_sync == 'true' ]]; then
      sudo rm -rf $afl_output/*
    fi

    # Build out init_instrument_fuzz variable
    echo 'Initializing AFL++ Container, Instrumenting TARGET, and Starting AFL++'
    afl_init_container="${docker_repo_root}/TARGET/init_aflplusplus_container.sh"
    afl_instrument_target="${docker_repo_root}/TARGET/instrument_target.sh ${target_source_name}"
    # Copy TARGET Test Cases to $afl_input Folder
    cp $target_test_cases/* $afl_input 2> /dev/null

    init_instrument_fuzz="${afl_init_container} && ${afl_instrument_target} && ${fuzz_session_init}"

    if [[ $debug == 'true' ]]; then
      echo 'Preparing to exec:'
      echo -e "${init_instrument_fuzz}\n\n\n"
      while true; do
        printf 'Proceed with Execution? <y||n>'; read answer
        case $answer in
          'y'|'Y') break;;
          'n'|'N') echo 'Aborting Execution...Goodbye.'; exit 0;;
        esac
      done
    fi
    
    # Instrument & Run Main
    if [[ -d /sys/devices/systemc/cpu ]]; then 
      sudo /bin/bash \
        --login \
        -c "
          cd /sys/devices/systemc/cpu &&
          echo performance | tee cpu*/cpufreq/scaling_governor
        "
    fi

    sudo sysctl -w kernel.unprivileged_userns_clone=1

    # NOTE: DEPENDING ON YOUR NEEDS, YOU MAY NEED TO ASSIGN MORE
    # BIND MOUNTS TO THE DOCKER CONTAINER
    docker_name="aflplusplus.${this_session_rand}"
    tmux new -s "afl_M_$this_session_rand" \
      "docker run \
        --privileged \
        --rm \
        --name \"${docker_name}\" \
        --mount type=bind,source=$this_repo_root,target=$docker_repo_root \
        --mount type=bind,source=$fuzz_session_root,target=$fuzz_session_root \
        --interactive \
        --tty aflplusplus/aflplusplus:dev \
        /bin/bash --login \
          -c \"${init_instrument_fuzz}\"
      "
    
    sudo sysctl -w kernel.unprivileged_userns_clone=0
    ;;

  'secondary')
    # Run Secondary
    afl_main_name=`docker ps -a | grep aflplusplus.$target_name | awk '{print $NF}'`
    tmux new -s "afl_S_$this_session_rand" \
      "docker exec \
        --interactive \
        --tty $afl_main_name \
        /bin/bash --login \
        -c \"${fuzz_session_init}\"
      "
      ;;

  *) usage;;
esac
