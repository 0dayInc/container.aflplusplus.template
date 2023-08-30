#!/bin/bash --login
other_repos_root='/opt'
docker_repo_root="${other_repos_root}/container.aflplusplus.template"
aflplusplus_source_root='/AFLplusplus'
custom_mutators_root="${aflplusplus_source_root}/custom_mutators"
radamsa_root="${other_repos_root}/radamsa"

aflpp_mutator="${custom_mutators_root}/aflpp"
atnwalk_mutator="${custom_mutators_root}/atnwalk"
gramatron_mutator="${custom_mutators_root}/gramatron"
honggfuzz_mutator="${custom_mutators_root}/honggfuzz"
libafl_base_mutator="${custom_mutators_root}/libafl_base"
libfuzzer_mutator="${custom_mutators_root}/libfuzzer"
symcc_mutator="${custom_mutators_root}/symcc"
symqemu_mutator="${custom_mutators_root}/symqemu"
radamsa_mutator="${custom_mutators_root}/radamsa"

fuzz_session_root='/fuzz_session'
target_prefix="${fuzz_session_root}/TARGET"

# Ensure instrumentation_globals.sh is always sourced
echo "source ${docker_repo_root}/TARGET/instrumentation_globals.sh" >> /etc/bash.bashrc

# Initialize Docker Container w Tooling ----------------------------------#
apt update
apt full-upgrade -y
apt install -y \
  subversion \
  libssl-dev \
  pkg-config \
  strace \
  netstat-nat \
  net-tools \
  apt-file \
  tcpdump \
  lsof \
  psmisc \
  logrotate \
  curl \
  openssh-server \
  git \
  binutils-dev \
  libunwind-dev \
  libblocksruntime-dev \
  clang

# Build ALL of AFL++ in the Container
cd $aflplusplus_source_root && make all && make install

# Install Radamsa to Support -R flag in afl-fuzz
# (i.e. Include Radamsa for test case mutation)
cd $other_repos_root && git clone https://gitlab.com/akihe/radamsa.git
cd $radamsa_root && make && make install

# Make Custom Mutators
cd $aflpp_mutator && make
cd $atnwalk_mutator && make
cd $gramatron_mutator && ./build_gramatron_mutator.sh
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
