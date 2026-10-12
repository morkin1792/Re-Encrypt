#!/usr/bin/env bash
# install.sh — copy the skill into a project (or your home) so any Claude Code session there has it.
#
#   ./install.sh                 # into ./.claude/skills of the current directory
#   ./install.sh /path/to/proj   # into that project's .claude/skills
#   ./install.sh --user          # into ~/.claude/skills (every project)
#   ./install.sh --link /path    # symlink instead of copy (edits here take effect immediately)
#
# The folder keeps its name on purpose: Claude Code matches the directory name against the `name:`
# field in SKILL.md. Start a NEW session in the target directory afterwards — skills are discovered
# at session start.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/skills/decrypt-app-traffic"
[ -f "$src/SKILL.md" ] || { echo "cannot find $src/SKILL.md" >&2; exit 1; }

mode=copy
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --user) target="$HOME/.claude/skills" ;;
    --link) mode=link ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) target="${1%/}/.claude/skills" ;;
  esac
  shift
done
[ -n "$target" ] || target="$PWD/.claude/skills"

mkdir -p "$target"
dest="$target/decrypt-app-traffic"
if [ -e "$dest" ] || [ -L "$dest" ]; then
  printf 'replace existing %s ? [y/N] ' "$dest"
  read -r answer
  case "$answer" in [yY]*) rm -rf "$dest" ;; *) echo "left unchanged"; exit 0 ;; esac
fi

if [ "$mode" = link ]; then
  ln -s "$src" "$dest"
  echo "linked  $dest -> $src"
else
  cp -r "$src" "$dest"
  echo "copied  $src -> $dest"
fi

echo
echo "Self-check:"
python3 "$dest/scripts/crypto-cli.py" selftest 2>/dev/null | tail -3
echo
echo "Next: open a NEW Claude Code session in $(dirname "$(dirname "$target")") and run"
echo "  /decrypt-app-traffic <dir-with-apks>"
echo "No app handy? Build three fixture apps with real encrypted traffic:"
echo "  python3 $dest/testdata/make-fixtures.py /tmp/skilltest --answers"
