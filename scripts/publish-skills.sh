#!/bin/bash
# Publish GhostMail skills to all agent registries
#
# Usage: ./scripts/publish-skills.sh [--clawhub] [--hermes] [--all]
#
# Prerequisites:
#   ClawHub:  npx clawhub login
#   Hermes:   hermes auth login

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { printf "${CYAN}[INFO]${NC} %s\n" "$1"; }
ok()    { printf "${GREEN}[OK]${NC} %s\n" "$1"; }
err()   { printf "${RED}[ERROR]${NC} %s\n" "$1" >&2; }

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SKILLS_DIR="$SCRIPT_DIR/skills"

publish_clawhub() {
    info "Publishing to ClawHub (OpenClaw)..."

    if ! command -v npx >/dev/null 2>&1; then
        err "npx not found. Install Node.js first."
        return 1
    fi

    npx clawhub@latest publish "$SKILLS_DIR/ghostmail-deploy"
    ok "ghostmail-deploy published to ClawHub"

    npx clawhub@latest publish "$SKILLS_DIR/ghostmail-email"
    ok "ghostmail-email published to ClawHub"

    echo ""
    echo "  Users can install with:"
    echo "    npx clawhub install ghostmail-deploy"
    echo "    npx clawhub install ghostmail-email"
    echo ""
}

publish_hermes() {
    info "Publishing to HermesHub (Hermes Agent)..."

    if ! command -v hermes >/dev/null 2>&1; then
        err "hermes CLI not found. Install Hermes Agent first."
        return 1
    fi

    REPO="bigdestiny2/ghostmail"

    hermes skills publish "$SKILLS_DIR/ghostmail-deploy" --to github --repo "$REPO"
    ok "ghostmail-deploy published to HermesHub"

    hermes skills publish "$SKILLS_DIR/ghostmail-email" --to github --repo "$REPO"
    ok "ghostmail-email published to HermesHub"

    echo ""
    echo "  Users can install with:"
    echo "    hermes skills install github:$REPO/skills/ghostmail-deploy"
    echo "    hermes skills install github:$REPO/skills/ghostmail-email"
    echo ""
}

print_manual() {
    echo ""
    printf "${BOLD}Manual Publishing Steps:${NC}\n"
    echo ""
    echo "  SkillRepo (skillsrepo.dev):"
    echo "    1. Sign up at https://skillsrepo.dev"
    echo "    2. Upload skills/ghostmail-deploy/SKILL.md"
    echo "    3. Upload skills/ghostmail-email/SKILL.md"
    echo ""
    echo "  awesome-selfhosted:"
    echo "    1. Fork https://github.com/awesome-selfhosted/awesome-selfhosted"
    echo "    2. Add to Communication > Email > Complete Solutions:"
    echo ""
    echo "       - [GhostMail](https://github.com/bigdestiny2/ghostmail) - Zero-knowledge"
    echo "         encrypted email server with SMTP, IMAP, webmail, and per-message"
    echo "         envelope encryption. (\`AGPL-3.0\`) \`Go\`"
    echo ""
    echo "    3. Open a PR titled: \"Add GhostMail to Communication > Email\""
    echo ""
    echo "  Docker Hub:"
    echo "    Automated via GitHub Actions on tagged releases."
    echo "    Set these repo secrets:"
    echo "      DOCKERHUB_USERNAME = your Docker Hub username"
    echo "      DOCKERHUB_TOKEN    = your Docker Hub access token"
    echo ""
    echo "    Then tag a release:"
    echo "      git tag v1.0.0 && git push origin v1.0.0"
    echo ""
    echo "  Homebrew:"
    echo "    Create a tap repo (e.g., bigdestiny2/homebrew-tap) with a formula:"
    echo "    See: https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap"
    echo ""
}

# Parse args
DO_CLAWHUB=false
DO_HERMES=false
DO_ALL=false

if [ $# -eq 0 ]; then
    DO_ALL=true
fi

for arg in "$@"; do
    case "$arg" in
        --clawhub) DO_CLAWHUB=true ;;
        --hermes)  DO_HERMES=true ;;
        --all)     DO_ALL=true ;;
        --help|-h)
            echo "Usage: $0 [--clawhub] [--hermes] [--all]"
            echo ""
            echo "  --clawhub   Publish to ClawHub (OpenClaw)"
            echo "  --hermes    Publish to HermesHub (Hermes Agent)"
            echo "  --all       Publish to all registries"
            echo ""
            exit 0
            ;;
        *)
            err "Unknown option: $arg"
            exit 1
            ;;
    esac
done

echo ""
printf "${BOLD}GhostMail Skill Publisher${NC}\n"
echo ""

if $DO_ALL || $DO_CLAWHUB; then
    publish_clawhub || true
fi

if $DO_ALL || $DO_HERMES; then
    publish_hermes || true
fi

print_manual
