#!/usr/bin/env bash
# Update a running LKS Notary deployment from git.
#
#   cd /opt/lks-notary && ./deploy/update.sh
#
# Run it as the user that owns the files, not as root: the working tree belongs
# to a human, the service only reads it.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo ">>> Current version"
git log -1 --format='%h %s'

echo ">>> Fetching"
git pull --ff-only

echo ">>> Dependencies"
# Cheap when nothing changed, and catches the case where pyproject gained one.
.venv/bin/pip install -q -e . 2>&1 | grep -v "already satisfied" || true

echo ">>> Pending database migrations"
# Deliberately not applied automatically: the application user has no DDL
# rights, which is what stops a compromised service from dropping the audit
# log. Migrations are applied by a human, from an administrative account.
for f in sql/0*.sql; do
    echo "    $f"
done
echo "    Apply any new one with:  sudo mysql lks_notary < sql/<file>.sql"

echo ">>> Permissions"
chmod -R g+rX "$ROOT"

echo ">>> Restarting"
sudo systemctl restart lks-notary-api lks-notary-worker
sleep 4

echo ">>> Health"
curl -sS http://127.0.0.1:8010/health && echo
git log -1 --format='Now running %h %s'
