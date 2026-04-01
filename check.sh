#!/bin/bash
# ============================================================================
# Axios Supply Chain Attack — Detection Script (macOS/Linux)
# ============================================================================
# Checks if your system was affected by the axios@1.14.1 / axios@0.30.4
# supply chain attack that dropped a cross-platform RAT via plain-crypto-js.
#
# Source: StepSecurity, Socket.dev, GitHub Issue #10604
# ============================================================================

echo "============================================"
echo "  Axios Supply Chain Attack — Detection"
echo "============================================"
echo ""

# --- Resolve scan root ---
SCAN_ROOT="${1:-.}"
if [ ! -d "$SCAN_ROOT" ]; then
  echo "ERROR: '$SCAN_ROOT' is not a directory"
  exit 1
fi
SCAN_ROOT="$(cd "$SCAN_ROOT" && pwd -P)"  # -P resolves symlinks (e.g. /tmp -> /private/tmp on macOS)
echo "  Scan root: $SCAN_ROOT"
echo ""

FOUND=0

# --- Check 1: Installed axios version (global, runs once) ---
echo "[1/6] Checking installed axios version..."
if command -v npm &> /dev/null; then
  AXIOS_VER=$(npm list axios 2>/dev/null | grep -oE "1\.14\.1|0\.30\.4")
  if [ -n "$AXIOS_VER" ]; then
    echo "  !! AFFECTED: axios@${AXIOS_VER} found in node_modules"
    FOUND=1
  else
    echo "  OK: No compromised axios version installed"
  fi
else
  echo "  SKIP: npm not found"
fi

# --- Checks 2, 3, 4: Run recursively for each directory containing a lockfile ---
echo ""
echo "[2-4/6] Scanning for lockfiles recursively (excluding node_modules)..."
echo "  find root : $SCAN_ROOT"

# Collect all matching lockfiles first so we can log them
RAW_LOCKFILES=()
while IFS= read -r f; do
  RAW_LOCKFILES+=("$f")
done < <(find "$SCAN_ROOT" \( -name "package-lock.json" -o -name "yarn.lock" \) -not -path "*/node_modules/*" | sort)

echo "  lockfiles found: ${#RAW_LOCKFILES[@]}"
for f in "${RAW_LOCKFILES[@]}"; do
  echo "    $f"
done

# Deduplicate to unique directories
UNIQUE_DIRS=()
if [ ${#RAW_LOCKFILES[@]} -gt 0 ]; then
  while IFS= read -r dir; do
    UNIQUE_DIRS+=("$dir")
  done < <(printf '%s\n' "${RAW_LOCKFILES[@]}" | sed 's|/[^/]*$||' | sort -u)
fi

if [ ${#UNIQUE_DIRS[@]} -eq 0 ]; then
  echo "  SKIP: No lockfiles found under $SCAN_ROOT"
else
  TOTAL=${#UNIQUE_DIRS[@]}
  echo "  Unique directories to scan: $TOTAL"

  IDX=0
  for dir in "${UNIQUE_DIRS[@]}"; do
    IDX=$((IDX + 1))
    echo ""
    echo "  ── [$IDX/$TOTAL] $dir"

    # --- Check 2: Lockfile contains compromised axios version ---
    if [ -f "$dir/package-lock.json" ]; then
      # Match the axios entry (v2/v3: "node_modules/axios", v1: "axios": {) then
      # check if the version within those lines is the compromised one.
      # Two separate greps avoid the non-portable \| alternation in BRE on macOS.
      LOCK_HIT=$({ grep -A 3 '"node_modules/axios":' "$dir/package-lock.json"; \
                   grep -A 3 '"axios": {' "$dir/package-lock.json"; } \
                 | grep -E '"version": "(1\.14\.1|0\.30\.4)"')
      if [ -n "$LOCK_HIT" ]; then
        echo "    [2] !! AFFECTED: axios at compromised version found in package-lock.json"
        echo "        $LOCK_HIT"
        FOUND=1
      else
        echo "    [2] OK: package-lock.json clean"
      fi
    fi

    if [ -f "$dir/yarn.lock" ]; then
      # Match the axios block header, then check the version line beneath it.
      LOCK_HIT=$(grep -A 2 '^axios@' "$dir/yarn.lock" \
                 | grep -E 'version "(1\.14\.1|0\.30\.4)"')
      if [ -n "$LOCK_HIT" ]; then
        echo "    [2] !! AFFECTED: axios at compromised version found in yarn.lock"
        echo "        $LOCK_HIT"
        FOUND=1
      else
        echo "    [2] OK: yarn.lock clean"
      fi
    fi

    # --- Check 3: Lockfile git history ---
    GIT_ROOT=$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)
    if [ -n "$GIT_ROOT" ]; then
      GIT_HIT=$(git -C "$dir" log -p -- package-lock.json yarn.lock 2>/dev/null | grep -E "plain-crypto-js" | head -3)
      if [ -n "$GIT_HIT" ]; then
        echo "    [3] !! WARNING: plain-crypto-js appeared in lockfile history"
        echo "        $GIT_HIT"
        echo "        (System MAY have been compromised even if node_modules is clean now)"
        FOUND=1
      else
        echo "    [3] OK: No trace of plain-crypto-js in git history"
      fi
    else
      echo "    [3] SKIP: Not inside a git repository"
    fi

    # --- Check 4: Malicious dependency in node_modules ---
    if [ -d "$dir/node_modules/plain-crypto-js" ]; then
      echo "    [4] !! AFFECTED: node_modules/plain-crypto-js/ EXISTS"
      FOUND=1
    else
      echo "    [4] OK: plain-crypto-js not in node_modules"
      echo "        (Note: The malware self-destructs — absence does NOT guarantee safety)"
    fi
  done
fi

# --- Check 5: RAT artifacts on disk (global, runs once) ---
echo ""
echo "[5/6] Checking for RAT artifacts..."

# macOS
if [ "$(uname)" = "Darwin" ]; then
  if [ -f "/Library/Caches/com.apple.act.mond" ]; then
    echo "  !! CRITICAL: macOS RAT found at /Library/Caches/com.apple.act.mond"
    ls -la "/Library/Caches/com.apple.act.mond"
    FOUND=1
  else
    echo "  OK: macOS RAT artifact not found"
  fi
fi

# Linux
if [ -f "/tmp/ld.py" ]; then
  echo "  !! CRITICAL: Linux RAT found at /tmp/ld.py"
  ls -la "/tmp/ld.py"
  FOUND=1
else
  echo "  OK: Linux RAT artifact not found"
fi

# --- Check 6: Network connections to C2 (global, runs once) ---
echo ""
echo "[6/6] Checking for C2 connections..."
C2_CHECK=$(netstat -an 2>/dev/null | grep "142.11.206.73" || ss -tn 2>/dev/null | grep "142.11.206.73")
if [ -n "$C2_CHECK" ]; then
  echo "  !! CRITICAL: Active connection to C2 server (142.11.206.73)"
  echo "  $C2_CHECK"
  FOUND=1
else
  echo "  OK: No active C2 connections detected"
fi

# DNS check
DNS_CHECK=$(grep -r "sfrclak.com" /var/log/ 2>/dev/null | head -3)
if [ -n "$DNS_CHECK" ]; then
  echo "  !! WARNING: DNS queries to sfrclak.com found in logs"
  FOUND=1
fi

# --- Summary ---
echo ""
echo "============================================"
if [ $FOUND -eq 1 ]; then
  echo "  !! POTENTIAL COMPROMISE DETECTED"
  echo ""
  echo "  Immediate actions:"
  echo "  1. Pin axios to 1.14.0 or 0.30.3"
  echo "  2. rm -rf node_modules && npm ci"
  echo "  3. Rotate ALL credentials (npm tokens, AWS, SSH, API keys)"
  echo "  4. Block sfrclak.com and 142.11.206.73 at firewall"
  echo "  5. If RAT artifacts found: FULL SYSTEM REBUILD"
  echo ""
  echo "  Ref: https://github.com/axios/axios/issues/10604"
else
  echo "  ALL CLEAR — No indicators of compromise found"
  echo ""
  echo "  Preventive steps:"
  echo "  - Pin axios: npm install axios@1.14.0 --save-exact"
  echo "  - Use npm ci (not npm install) in CI/CD"
  echo "  - Set ignore-scripts=true in .npmrc"
  echo "  - Run: npm config set min-release-age 3"
fi
echo "============================================"
