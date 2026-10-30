#!/bin/sh
# Assemble the static site for Vercel into public/. The dashboard's CSS and JS are copied from the local
# product (src/tripwire/static) so the hosted demo always matches it; nothing in src/ is changed.
set -eu
cd "$(dirname "$0")/.."
rm -rf public
mkdir -p public/static public/pitch
cp src/tripwire/static/styles.css src/tripwire/static/app.js public/static/
cp web/index.html web/demo.css web/demo.js web/demo-player.js public/
cp docs/pitch/index.html public/pitch/index.html
echo "built public/: $(find public -type f | wc -l | tr -d ' ') files"
