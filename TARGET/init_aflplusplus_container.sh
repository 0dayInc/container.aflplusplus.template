#!/bin/bash --login
container_afl_template_path='/opt/container.aflplusplus.template'
instrumentation_globals="${container_afl_template_path}/TARGET/instrumentation_globals.sh"
source $instrumentation_globals

# Ensure the instrumentation_globals.sh is always sourced when executing bash
echo "source ${instrumentation_globals}" >> /etc/bash.bashrc

# Initialize Docker Container w Tooling ----------------------------------#
apt update
apt full-upgrade -y
apt install -y \
  apt-file \
  autoconf \
  binutils-dev \
  build-essential \
  clang \
  curl \
  coreutils \
  git \
  libblocksruntime-dev \
  libini-config-dev \
  libseccomp-dev \
  libssl-dev \
  libunwind-dev \
  logrotate \
  lsof \
  netstat-nat \
  net-tools \
  openssh-server \
  pkg-config \
  psmisc \
  strace \
  subversion \
  tcpdump

# Build Preeny to get Useful AFL_PRELOAD .so files
# See TARGET/instrumentation_globals.sh for more info
cd /opt && git clone https://github.com/zardus/preeny.git
cd $preeny_root && make

# Build ALL of AFL++ in the Container
# Per https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/INSTALL.md
# "distrib: everything (for both binary-only and source code fuzzing)"
cd /
if [[ -d $aflplusplus_source_root ]]; then
  rm -rf $aflplusplus_source_root
fi

# Let's snag latest dev branch and build with some custom options
git clone https://github.com/AFLplusplus/AFLplusplus.git --branch dev

cd $aflplusplus_source_root && make distrib # \
                               CODE_COVERAGE=1 \
                               LLVM_CONFIG="${preferred_llvm_config}"

cd $aflplusplus_source_root && make install

# Install Radamsa to Support -R flag in afl-fuzz
# (i.e. Include Radamsa for test case mutation)
radamsa_root="/opt/radamsa"
cd / && git clone https://gitlab.com/akihe/radamsa.git
cd $radamsa_root && make && make install

# Make Custom Mutators
aflpp_mutator=$(dirname $aflpp_so)
atnwalk_mutator=$(dirname $atnwalk_so)
autotokens_mutator=$(dirname $autotokens_so)
gramatron_mutator=$(dirname $gramatron_so)
grammar_mutator=$(dirname $grammar_so)
honggfuzz_mutator=$(dirname $honggfuzz_so)
libafl_base_mutator=$(dirname $libafl_base_so)
libfuzzer_mutator=$(dirname $libfuzzer_so)
radamsa_mutator=$(dirname $radamsa_so)
symcc_mutator=$(dirname $symcc_so)
symqemu_mutator=$(dirname $symqemu_so)
cd $aflpp_mutator && make
cd $atnwalk_mutator && make
cd $autotokens_mutator && make
cd $gramatron_mutator && ./build_gramatron_mutator.sh
cd $grammar_mutator && ./build_grammar_mutator.sh
cd $honggfuzz_mutator && make
cd $libafl_base_mutator && make
cd $libfuzzer_mutator && make
cd $radamsa_mutator && make
cd $symcc_mutator && make
cd $symqemu_mutator && make

# Configure logrotate to rotate logs every hour
logrotate_script='/usr/local/sbin/logrotate.sh'
mkdir /etc/logrotate.minute.d
echo 'include /etc/logrotate.minute.d' > /etc/logrotate.minute.conf
chmod 644 /etc/logrotate.minute.conf

cat << EOF | tee $logrotate_script
#!/bin/bash --login
/usr/sbin/logrotate /etc/logrotate.minute.conf
rm ${target_prefix}/logs/*_log.1
EOF
chmod 775 $logrotate_script

cat << EOF | tee /etc/logrotate.minute.d/TARGET
${target_prefix}/logs/fuzz.log {
  size 128M
  rotate 0
  copytruncate
  missingok
  notifempty
  nocreate
  nomail
}
EOF
(crontab -l 2>/dev/null; echo "* * * * * ${logrotate_script}") | crontab -

printf 'Starting Cron Daemon...'
cd / && /etc/init.d/cron start
echo 'complete.'
