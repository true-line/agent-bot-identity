#!/bin/bash
# Stage the formula's actual install method without fetching a release or linking a live keg.
set -euo pipefail
[[ "$(uname -s)" == Darwin ]]
repo="$(git rev-parse --show-toplevel)"
brew_bin="$(command -v brew)"
node_bin="$(command -v node)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
stage="$(cd "$stage" && pwd -P)"
mkdir -p "$stage"/{src,operator,home,tmp,bin,opt/node/bin}
ln -s "$node_bin" "$stage/opt/node/bin/node"
git -C "$repo" archive HEAD | tar -xf - -C "$stage/src"
cp "$repo/tests/fixtures/first-hq-challenge.json" "$(dirname "$0")/staged-owner-review.mjs" "$(dirname "$0")/discard-owner-review.py" "$stage/operator/"

cd "$stage/src"
env -i HOME="$stage/home" TMPDIR="$stage/tmp" PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
  HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_DEVELOPER=1 HOMEBREW_NO_INSTALL_FROM_API=1 \
  HOMEBREW_TEMP="$stage/tmp" HOMEBREW_CACHE="$stage/cache" HOMEBREW_LOGS="$stage/logs" \
  "$brew_bin" ruby -e '
    require "formulary"
    stage = Pathname.pwd.parent
    recipe = Pathname.pwd/"Formula/agent-bot.rb"
    formula = Formulary.from_contents("agent-bot", recipe, recipe.read, tap: Tap.fetch("smoke", "staged"))
    keg = stage/"Cellar/agent-bot/candidate"
    opt = stage/"opt/agent-bot"
    formula.define_singleton_method(:prefix) { keg }
    formula.define_singleton_method(:opt_prefix) { opt }
    formula.define_singleton_method(:formula_opt_prefix) { |name| stage/"opt"/name }
    (keg/"bin").mkpath
    File.symlink(keg, opt)
    formula.install
  '
ln -s ../opt/agent-bot/bin/agent-bot "$stage/bin/agent-bot"
cd "$stage/operator"
env -i HOME="$stage/home" TMPDIR="$stage/tmp" PATH="/usr/bin:/bin" \
  "$node_bin" staged-owner-review.mjs "$stage"
