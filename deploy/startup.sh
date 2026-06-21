#!/usr/bin/env sh

# thesada-app self-host bootstrap: scaffold env + secrets, migrate, start.
# Idempotent - re-running leaves an existing app.env untouched.
set -eu
cd "$(dirname "$0")"

command -v docker >/dev/null 2>&1 || { echo "error: docker not found"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "error: docker compose v2 required"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "error: openssl not found"; exit 1; }

# hex secrets only (no sed-breaking chars).
gen() { openssl rand -hex "${1:-24}"; }

if [ ! -f app.env ]; then
  echo "scaffolding app.env + db.env with generated secrets..."
  DB_PASS="$(gen 18)"
  sed -e "s|CHANGEME_DB_PASSWORD|${DB_PASS}|g" \
      -e "s|^THESADA_COOKIE_SECRET=.*|THESADA_COOKIE_SECRET=$(gen 32)|" \
      -e "s|^THESADA_CA_KEY_PASSPHRASE=.*|THESADA_CA_KEY_PASSPHRASE=$(gen 24)|" \
      app.env.example > app.env
  sed -e "s|CHANGEME_DB_PASSWORD|${DB_PASS}|g" db.env.example > db.env
  chmod 600 app.env db.env
else
  echo "app.env exists - leaving it as-is"
fi

echo "pulling images..."
docker compose pull

# one-shot; aborts before the app starts if a migration fails.
echo "applying database migrations..."
docker compose run --rm app migrate

echo "starting the stack..."
docker compose up -d

cat <<'EOF'

thesada-app is up on http://127.0.0.1:8080 (front it with a TLS reverse proxy).

Next steps:
  1. Set THESADA_ADMIN_EMAIL and the SMTP_* values in app.env, then: docker compose up -d
  2. The first super-admin's one-shot login link is in the logs: docker compose logs app
EOF
