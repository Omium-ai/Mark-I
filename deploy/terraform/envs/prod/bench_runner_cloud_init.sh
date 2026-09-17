#!/bin/bash
# First boot of the pinned bench runner (bench/RUNNER.md). Installs the GitHub runner as a
# systemd service under /opt/runner and an idle timer that stops the instance after 20 quiet minutes.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q build-essential cmake pkg-config libssl-dev clang git curl jq unzip
curl -sSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscli.zip
unzip -q /tmp/awscli.zip -d /tmp && /tmp/aws/install && rm -rf /tmp/aws /tmp/awscli.zip

useradd -m -s /bin/bash runner
install -d -o runner -g runner /opt/runner
cd /opt/runner
VER=$(curl -sSL https://api.github.com/repos/actions/runner/releases/latest | jq -r .tag_name | sed 's/^v//')
curl -sSL -o runner.tgz "https://github.com/actions/runner/releases/download/v${VER}/actions-runner-linux-x64-${VER}.tar.gz"
sudo -u runner tar xzf runner.tgz && rm runner.tgz
TOKEN=$(aws ssm get-parameter --region us-east-1 --name /omium/mark1/bench-runner/registration-token --with-decryption --query Parameter.Value --output text)
sudo -u runner ./config.sh --unattended --url https://github.com/Omium-ai/Mark-I --token "$TOKEN" \
  --name mark1-bench-c7i2xl --labels mark1-bench-c7i2xl --replace
./svc.sh install runner
./svc.sh start

cat >/usr/local/bin/runner-idle-stop <<'SH'
#!/bin/bash
# Runner.Worker exists only while a job runs; four quiet 5-minute checks in a row = stop the box.
if pgrep -f Runner.Worker >/dev/null; then echo 0 >/run/runner-idle; exit 0; fi
n=$(( $(cat /run/runner-idle 2>/dev/null || echo 0) + 1 ))
echo "$n" >/run/runner-idle
[ "$n" -ge 4 ] && shutdown -h now
exit 0
SH
chmod +x /usr/local/bin/runner-idle-stop
cat >/etc/systemd/system/runner-idle-stop.service <<'UNIT'
[Service]
Type=oneshot
ExecStart=/usr/local/bin/runner-idle-stop
UNIT
cat >/etc/systemd/system/runner-idle-stop.timer <<'UNIT'
[Timer]
OnBootSec=10min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now runner-idle-stop.timer
