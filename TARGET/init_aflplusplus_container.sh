#!/bin/bash --login
container_afl_template_path='/opt/container.aflplusplus.template'
instrumentation_globals="${container_afl_template_path}/TARGET/instrumentation_globals.sh"
source $instrumentation_globals

# Ensure instrumentation_globals.sh is always sourced
echo "source ${instrumentation_globals}" >> /etc/bash.bashrc

# Initialize Docker Container w Tooling ----------------------------------#
apt update
apt full-upgrade -y
apt install -y \
  apt-file \
  binutils-dev \
  clang \
  curl \
  coreutils \
  git \
  libblocksruntime-dev \
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

# Build ALL of AFL++ in the Container
# Per https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/INSTALL.md
# "distrib: everything (for both binary-only and source code fuzzing)"
cd /
if [[ -d $aflplusplus_source_root ]]; then
  rm -rf $aflplusplus_source_root
fi
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd $aflplusplus_source_root && git checkout dev && make distrib && make install

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
honggfuzz_mutator=$(dirname $honggfuzz_so)
libafl_base_mutator=$(dirname $libafl_base_so)
libfuzzer_mutator=$(dirname $libfuzzer_so)
radamsa_mutator=$(dirname $radamsa_so)
symqemu_mutator=$(dirname $symqemu_so)
cd $aflpp_mutator && make
cd $atnwalk_mutator && make
cd $autotokens_mutator && make
cd $gramatron_mutator && ./build_gramatron_mutator.sh
cd $honggfuzz_mutator && make
cd $libafl_base_mutator && make
cd $libfuzzer_mutator && make
cd $radamsa_mutator && make
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
