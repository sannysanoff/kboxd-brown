#!/usr/bin/env bash

# Validate commit hygiene for all non-merge commits after the
# introduction point.  Checks:
#   1. Subject line format (capitalized, length, no trailing period)
#   2. WIP commit detection
#
# Usage:
#   scripts/check-commitlog.sh [--quiet|-q] [--range REV_RANGE]
#
# Exit 0 on success, 1 on validation failure.

# --- bootstrap common helpers ---
common_script="$(dirname "$0")/common.sh"
[ -r "$common_script" ] || {
    echo "[!] '$common_script' not found." >&2
    exit 1
}
bash -n "$common_script" > /dev/null 2>&1 || {
    echo "[!] '$common_script' has syntax errors." >&2
    exit 1
}
source "$common_script"
declare -F set_colors > /dev/null 2>&1 || {
    echo "[!] '$common_script' missing set_colors." >&2
    exit 1
}
set_colors

QUIET=false
REV_RANGE=""
RANGE_START=""
RANGE_END=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quiet | -q)
            QUIET=true
            shift
            ;;
        --range)
            [[ $# -ge 2 ]] || {
                echo "Missing value for --range" >&2
                exit 1
            }
            REV_RANGE="$2"
            shift 2
            ;;
        --range=*)
            REV_RANGE="${1#*=}"
            shift
            ;;
        --help | -h)
            echo "Usage: $0 [--quiet|-q] [--range REV_RANGE] [--help|-h]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# History cutoff: commits at or before this one are not validated.  The
# root commit is used so that the cutoff survives history rewrites.
BASE_COMMIT=$(git rev-list --max-parents=0 HEAD | tail -1)

if [[ -n "$REV_RANGE" ]]; then
    if [[ "$REV_RANGE" == *..* ]]; then
        RANGE_START="${REV_RANGE%%..*}"
        RANGE_END="${REV_RANGE##*..}"
        if ! git rev-parse --verify "${RANGE_START}^{commit}" > /dev/null 2>&1; then
            # A rewritten history leaves no object for a recorded old tip.
            # Fall back to validating everything reachable from the range end.
            echo -e "${YELLOW}Range start ${RANGE_START} not found; checking all history.${NC}" >&2
            RANGE_START=""
        fi
    else
        RANGE_END="$REV_RANGE"
    fi
    if ! git rev-parse --verify "${RANGE_END}^{commit}" > /dev/null 2>&1; then
        throw "Revision range end %s not found." "$RANGE_END"
    fi
else
    RANGE_START="$BASE_COMMIT"
    RANGE_END="HEAD"
    REV_RANGE="${RANGE_START}..${RANGE_END}"
fi

rev_list_args=("$RANGE_END" "^$BASE_COMMIT")
if [[ -n "$RANGE_START" ]]; then
    rev_list_args+=("^$RANGE_START")
fi

REPAIR_BASE="${RANGE_START:-$BASE_COMMIT}"

commits=$(git rev-list --no-merges "${rev_list_args[@]}")
if [ -z "$commits" ]; then
    $QUIET || echo -e "${GREEN}No commits to check.${NC}"
    exit 0
fi

# --- validate each commit ---
failed=0
warnings=0
suspicious=()

while IFS= read -r commit; do
    [ -z "$commit" ] && continue

    sh=$(git show -s --format=%h "$commit")
    subj=$(git show -s --format=%s "$commit")

    issues=""
    warns=""
    has_issue=0
    has_warn=0

    # 1. WIP prefix
    if [[ "$subj" =~ ^[Ww][Ii][Pp][[:space:]]*: ]]; then
        has_warn=1
        warns+="Work-in-progress commit|"
        ((warnings++))
    fi

    # 2. Subject format
    subj_len=${#subj}
    first="${subj:0:1}"
    last="${subj: -1}"

    if [[ $subj_len -le 10 ]]; then
        has_warn=1
        warns+="Subject very short ($subj_len chars)|"
        ((warnings++))
    elif [[ $subj_len -ge 80 ]]; then
        has_issue=1
        issues+="Subject too long ($subj_len chars)|"
        ((failed++))
    fi

    case "$first" in
        [a-z])
            has_issue=1
            issues+="Subject not capitalized|"
            ((failed++))
            ;;
    esac

    if [[ "$last" == "." ]]; then
        has_issue=1
        issues+="Subject ends with period|"
        ((failed++))
    fi

    # --- report ---
    if [[ $has_issue -eq 1 || $has_warn -eq 1 ]]; then
        echo -e "${YELLOW}Commit ${sh}:${NC} ${subj}"

        if [[ $has_issue -eq 1 ]]; then
            IFS='|' read -ra arr <<< "${issues%|}"
            for i in "${arr[@]}"; do
                [ -n "$i" ] && echo -e "  [ ${RED}FAIL${NC} ] $i"
            done
            suspicious+=("$sh: $subj")
        fi

        if [[ $has_warn -eq 1 ]]; then
            IFS='|' read -ra arr <<< "${warns%|}"
            for w in "${arr[@]}"; do
                [ -n "$w" ] && echo -e "  ${YELLOW}!${NC} $w"
            done
        fi
    fi
done <<< "$commits"

if [[ $failed -gt 0 ]]; then
    echo -e "\n${RED}Problematic commits:${NC}"
    for c in "${suspicious[@]}"; do
        echo -e "  ${RED}-${NC} $c"
    done
    echo -e "\n${RED}Recommended actions:${NC}"
    echo -e "1. Verify hooks: ${YELLOW}make install-hooks${NC}"
    echo -e "2. Never use ${YELLOW}--no-verify${NC}"
    echo -e "3. Avoid GitHub web interface for commits"
    echo -e "4. Amend if needed: ${YELLOW}git rebase -i ${REPAIR_BASE}${NC}"
    echo
    throw "Commit-log validation failed."
fi

if [[ $warnings -gt 0 ]]; then
    $QUIET || echo -e "\n${YELLOW}Some commits have quality warnings but passed validation.${NC}"
fi

$QUIET || echo -e "${GREEN}All commits OK.${NC}"
exit 0
