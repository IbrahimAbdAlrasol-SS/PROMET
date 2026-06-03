# PROMET — Full Environment Setup Prompt
# Give this entire file to Claude Code CLI and say: "Follow these instructions"

---

You are setting up the PROMET Android Security Assessment environment.
Your job is to read all skills, install all required tools, and verify the
environment is real — no UI mocking, no simulation of tool output.

---

## STEP 1 — Read All Skills

Read every file below in full before doing anything else.
These are your operating instructions for the entire project.

Skills to read (in this order):

1. AGENTS.md              — session contract, mission, rules
2. WORKFLOW.md            — 13-phase analysis workflow
3. TOOLS.md               — tool reference and command recipes
4. FINDINGS-DB.md         — SQLite database schema and CLI
5. FINDINGS-PRIORITIZATION.md  — severity and OWASP mapping
6. DATAFLOW-VALIDATION.md      — 5-step source-to-sink validation
7. EXPLOIT-METHODOLOGY.md      — PoC development strategy
8. EXPLOIT-VERIFICATION.md     — proof levels and bypass protocol
9. EXPLOITATION-QUEUE.md       — vuln-to-exploit handoff schema
10. DETECTION-PAIRING.md       — YARA, Sigma, IOC generation
11. SEMGREP-GUIDE.md           — Semgrep setup and custom rules
12. CODEQL-GUIDE.md            — CodeQL setup and taint queries
13. NATIVE-FUZZING.md          — AFL++ fuzzing for native libs
14. SESSION-MEMORY.md          — persistent memory system
15. TROUBLESHOOTING.md         — failure recovery
16. README.md                  — environment overview

Do not skip any file. Do not summarize — read the full content.

---

## STEP 2 — Install Required Tools

Install every tool below. Verify each one after installation.
Do NOT mock or simulate any tool. Every tool must be real and executable.

### Core Android Tools
- Android Studio (includes ADB, AVD Manager, Android SDK)
- Android SDK Platform Tools (adb, fastboot)
- Android Emulator — create AVD: Pixel 7, API 34, google_apis, x86_64
- Java 17+ (required for jadx and apktool)

### Static Analysis
- jadx          → decompile APK to Java/Kotlin source
- apktool       → decode APK resources and smali
- semgrep       → pip install semgrep
- codeql        → download from github.com/github/codeql-cli-binaries

### Dynamic Analysis
- frida-tools   → pip install frida-tools
- frida-server  → download matching version for Android x86 from frida.re
- mitmproxy     → pip install mitmproxy

### Supporting Tools
- python 3.12+
- sqlite3       → built into Python
- tmux          → for managing multiple terminal panes
- git

### Verification — run after each install:
```
adb version
jadx --version
apktool --version
frida --version
mitmproxy --version
semgrep --version
python --version
sqlite3 --version
```

If any tool fails — stop and fix it before continuing.
Do NOT proceed with a broken tool.

---

## STEP 3 — Setup Android Emulator (REAL — NO SIMULATION)

CRITICAL RULE: The emulator must be a real Android Virtual Device.
Do NOT simulate emulator output. Do NOT mock adb responses.
Every command must run against a real running emulator process.

### Create the AVD
```
avdmanager create avd \
  --name re-pixel7-api34 \
  --package "system-images;android-34;google_apis;x86_64" \
  --device "pixel_7"
```

### Start the emulator
```
emulator -avd re-pixel7-api34 -no-snapshot-load
```

### Verify it is real and running
```
adb wait-for-device
adb shell getprop sys.boot_completed   # must return 1
adb shell id                           # must return uid=2000(shell)
adb devices                            # must show emulator-XXXX device
```

### Setup mitmproxy CA on emulator
```
mitmproxy --version
adb shell settings put global http_proxy 10.0.2.2:8080
```

### Deploy Frida server
```
# Push frida-server to emulator
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Verify frida is connected to REAL device
frida-ps -U   # must list real running processes
```

If frida-ps shows no processes or fake output — stop and fix.

---

## STEP 4 — Setup Frida Hooks

Copy these hook files into the project scripts directory:

- frida-bypass-certificate-pinner.js
- frida-hook-build-fields.js
- frida-hook-crypto.js
- frida-hook-file-exists.js
- frida-hook-intent.js
- frida-hook-network.js
- frida-hook-shared-prefs.js
- frida-hook-url-log.js
- frida-hook-webview.js
- frida-spoof-build.js

Verify hooks load without errors:
```
frida -U -n com.android.settings -l frida-hook-build-fields.js -q
```
Must attach to real emulator process — not simulated.

---

## STEP 5 — Initialize Findings Database

```python
import sqlite3
conn = sqlite3.connect("findings.db")
# Create all 6 tables: hosts, services, vulns, credentials, chains, session_log
# Schema defined in FINDINGS-DB.md
```

Verify database is created and all tables exist:
```
sqlite3 findings.db ".tables"
# Expected: chains  credentials  hosts  services  session_log  vulns
```

---

## STEP 6 — Final Health Check

Run this checklist. Every item must be GREEN before accepting any APK:

```
[ ] adb devices shows running emulator
[ ] sys.boot_completed = 1
[ ] frida-ps -U lists real processes (10+ processes minimum)
[ ] mitmproxy listener active on port 8080
[ ] jadx --version returns version string
[ ] apktool --version returns version string
[ ] semgrep --version returns version string
[ ] sqlite3 findings.db ".tables" shows all 6 tables
[ ] All 10 frida hook files present in scripts/
```

If any item fails — fix it before reporting setup complete.

---

## STEP 7 — Ready Confirmation

Only report setup complete when ALL of the following are true:

1. All 16 skill files have been read in full
2. All tools installed and verified with real version output
3. Real Android emulator is running and reachable via adb
4. Real Frida server is running on emulator (not simulated)
5. mitmproxy is listening and ready
6. findings.db initialized with all 6 tables
7. All Frida hook files are present

When ready, say:
"PROMET environment is ready. Drop an APK to begin analysis."

---

## HARD RULES — Never Break These

- NEVER simulate adb output
- NEVER mock frida-ps results
- NEVER pretend a tool is installed when it is not
- NEVER skip a skill file
- NEVER proceed past a failed health check
- If something fails, report the exact error and stop
