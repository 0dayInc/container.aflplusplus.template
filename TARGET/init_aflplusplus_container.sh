#!/bin/bash --login
other_repos_root='/opt'
docker_repo_root="${other_repos_root}/container.aflplusplus.wrapper"
custom_mutators_root="${other_repos_root}/AFLplusplus/custom_mutators"
radamsa_root="${other_repos_root}/radamsa"
honggfuzz_root="${custom_mutators_root}/honggfuzz"

fuzz_session_root='/fuzz_session'
target_prefix="${fuzz_session_root}/TARGET"

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
  git

# Install Radamsa to Support -R flag in afl-fuzz
# (i.e. Include Radamsa for test case mutation)
cd $other_repos_root
git clone https://github.com/AFLplusplus/AFLplusplus
git clone https://gitlab.com/akihe/radamsa.git

# Make Honggfuzz
cd $honggfuzz_root
make

# Build Radamsa
cd $radamsa_root
make
make install

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
