#!/bin/sh
# Assemble the static site for Vercel into public/.
#   /      the landing page (web/landing.html + web/landing.css): what Tripwire is, features, quotable numbers, install
#   /app   the dashboard as a product with a Demo tab, generated from the local dashboard's own page
#          (src/tripwire/static) so the hosted app always matches it; nothing in src/ is changed.
# cleanUrls in vercel.json serves public/app.html at /app. The pitch deck (docs/pitch) is deliberately not part of the site.
set -eu
cd "$(dirname "$0")/.."
rm -rf public
mkdir -p public/static
cp src/tripwire/static/styles.css src/tripwire/static/app.js public/static/
node web/build_page.mjs src/tripwire/static/index.html public/app.html
cp web/demo.css web/demo.js web/demo-player.js public/
cp web/landing.html public/index.html
cp web/landing.css public/landing.css
echo "built public/: $(find public -type f | wc -l | tr -d ' ') files"
