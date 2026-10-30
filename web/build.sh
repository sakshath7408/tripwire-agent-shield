#!/bin/sh
# Assemble the static site for Vercel into public/. The dashboard's page, CSS and JS come from the local
# product (src/tripwire/static) so the hosted app always matches it; nothing in src/ is changed.
# The pitch deck (docs/pitch) is deliberately not part of the site.
set -eu
cd "$(dirname "$0")/.."
rm -rf public
mkdir -p public/static
cp src/tripwire/static/styles.css src/tripwire/static/app.js public/static/
node web/build_page.mjs src/tripwire/static/index.html public/index.html
cp web/demo.css web/demo.js web/demo-player.js public/
echo "built public/: $(find public -type f | wc -l | tr -d ' ') files"
