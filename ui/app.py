#!/usr/bin/env python3
"""PROMET Web UI — Android Security Analysis Chat Interface"""

import asyncio
import json
import os
import re
import shutil
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Optional

import aiofiles
import anthropic
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

load_dotenv(Path(__file__).parent / ".env")

# ── Configuration ──────────────────────────────────────────────────────────────
MODEL      = os.environ.get("PROMET_MODEL", "claude-opus-4-8")
MAX_TOKENS = int(os.environ.get("PROMET_MAX_TOKENS", "8192"))
PORT       = int(os.environ.get("PORT", "8765"))

def _detect_shell() -> str:
    """Auto-detect the best shell on this OS."""
    forced = os.environ.get("PROMET_SHELL", "").strip()
    if forced:
        return forced
    if sys.platform != "win32":
        return "bash"
    # Windows: look for Git Bash in common locations
    candidates = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
        r"C:\Users\%s\scoop\apps\git\current\bin\bash.exe" % os.environ.get("USERNAME", ""),
        r"C:\msys64\usr\bin\bash.exe",
        r"C:\cygwin64\bin\bash.exe",
    ]
    for p in candidates:
        if Path(p).exists():
            return p
    # Last resort: cmd.exe
    return "cmd.exe"

SHELL = _detect_shell()
PROMPTS_DIR   = Path(__file__).parent.parent          # repo root with *.md files
UPLOAD_DIR    = Path(tempfile.gettempdir()) / "promet-uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# ── System prompt ──────────────────────────────────────────────────────────────
_MD_ORDER = [
    "AGENTS.md", "WORKFLOW.md", "TOOLS.md", "FINDINGS-DB.md",
    "FINDINGS-PRIORITIZATION.md", "DATAFLOW-VALIDATION.md",
    "EXPLOIT-METHODOLOGY.md", "EXPLOIT-VERIFICATION.md",
    "EXPLOITATION-QUEUE.md", "DETECTION-PAIRING.md",
    "SEMGREP-GUIDE.md", "CODEQL-GUIDE.md", "NATIVE-FUZZING.md",
    "SESSION-MEMORY.md", "TROUBLESHOOTING.md", "README.md",
]

def _build_system_prompt() -> str:
    header = (
        "You are PROMET — an expert Android security researcher and penetration tester.\n"
        "You operate within this Android RE workspace. Follow the phased workflow exactly.\n"
        "Use the bash tool to run every command. Never simulate or mock tool output.\n"
        "Announce each phase as you enter it, e.g. '## Phase 3: Static Triage'.\n"
        "Write findings to the workspace incrementally — never batch at the end.\n"
        "\n" + "=" * 72 + "\n\n"
    )
    parts = [header]
    for fname in _MD_ORDER:
        fpath = PROMPTS_DIR / fname
        if fpath.exists():
            parts.append(f"<!-- {fname} -->\n")
            parts.append(fpath.read_text(encoding="utf-8", errors="replace"))
            parts.append("\n\n")
    return "".join(parts)

SYSTEM_PROMPT: str = _build_system_prompt()

# ── Tool definitions ───────────────────────────────────────────────────────────
TOOLS = [
    {
        "name": "bash",
        "description": (
            "Execute a shell command on the host machine. "
            "Use for adb, jadx, apktool, frida, mitmproxy, semgrep, python3, sqlite3, "
            "and every other analysis tool. Commands run with full host permissions."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to execute"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 120, max 600)", "default": 120},
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": "Read the full contents of any file from the filesystem.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute or relative path to the file"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file, creating parent directories as needed.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path":    {"type": "string", "description": "Destination path"},
                "content": {"type": "string", "description": "File content"},
                "mode":    {"type": "string", "enum": ["write", "append"], "default": "write"},
            },
            "required": ["path", "content"],
        },
    },
]

# ── Phase detection ────────────────────────────────────────────────────────────
_PHASE_RE: dict[int, re.Pattern] = {
    0:  re.compile(r"phase\s*0|environment.{0,10}valid|doctor|baseline.{0,10}health", re.I),
    1:  re.compile(r"phase\s*1|boot.{0,10}emulat|emulat.{0,10}boot|avd.{0,10}start", re.I),
    2:  re.compile(r"phase\s*2|target.{0,10}intake|package.{0,10}name|apk.{0,10}hash", re.I),
    3:  re.compile(r"phase\s*3[^\.0-9]|static.{0,10}triage|jadx|apktool|decompil", re.I),
    4:  re.compile(r"phase\s*4|install.{0,10}launch|smoke.{0,10}test|adb.{0,10}install", re.I),
    5:  re.compile(r"phase\s*5[^\.5]|network.{0,10}intercep|mitmproxy|proxy.{0,10}set", re.I),
    6:  re.compile(r"phase\s*6|exercise.{0,10}app|ui.{0,10}explor|agent.device", re.I),
    7:  re.compile(r"phase\s*7|prepare.{0,10}frida|frida.{0,10}start|frida.{0,10}attach", re.I),
    8:  re.compile(r"phase\s*8|anti.analys|hooking|bypass.{0,10}check", re.I),
    9:  re.compile(r"phase\s*9[^\.5]|poc|proof.of.concept|exploit.script", re.I),
    10: re.compile(r"phase\s*10[^\.5]|confidence.{0,10}review|chain.{0,10}review", re.I),
    11: re.compile(r"phase\s*11|backup.{0,10}extract", re.I),
    12: re.compile(r"phase\s*12|magisk|zygisk|advanced.{0,10}bypass", re.I),
    13: re.compile(r"phase\s*13|encrypt.{0,10}dex|packed.{0,10}dex", re.I),
}

def _detect_phase(text: str) -> Optional[int]:
    for num, pat in _PHASE_RE.items():
        if pat.search(text):
            return num
    return None

# ── Anthropic client (lazy init) ───────────────────────────────────────────────
def _make_client() -> Optional[anthropic.AsyncAnthropic]:
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    return anthropic.AsyncAnthropic(api_key=key) if key else None

_client: Optional[anthropic.AsyncAnthropic] = _make_client()

# ── Claude Code CLI detection ──────────────────────────────────────────────────
def _find_claude_bin() -> str:
    """Locate the claude CLI binary on this machine."""
    forced = os.environ.get("PROMET_CLAUDE_BIN", "").strip()
    if forced:
        return forced
    if sys.platform == "win32":
        user = os.environ.get("USERNAME", "")
        candidates = [
            rf"C:\Users\{user}\AppData\Roaming\npm\claude.cmd",
            rf"C:\Users\{user}\scoop\shims\claude.cmd",
            rf"C:\Users\{user}\AppData\Local\Programs\claude\claude.cmd",
            r"C:\Program Files\nodejs\claude.cmd",
            "claude.cmd",
            "claude",
        ]
        for c in candidates:
            if shutil.which(c) or Path(c).exists():
                return c
        return "claude.cmd"
    found = shutil.which("claude")
    return found or "claude"

CLAUDE_BIN: str = _find_claude_bin()

# ── Session storage (in-memory) ────────────────────────────────────────────────
_sessions: dict[str, list] = {}

# ── Tool executors ─────────────────────────────────────────────────────────────
async def _exec_bash(ws: WebSocket, command: str, timeout: int = 120) -> str:
    timeout = min(max(timeout, 5), 600)
    # cmd.exe uses /c instead of -c
    shell_flag = "/c" if SHELL.lower().endswith("cmd.exe") else "-c"
    try:
        proc = await asyncio.create_subprocess_exec(
            SHELL, shell_flag, command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        chunks: list[str] = []

        async def _drain():
            async for raw_line in proc.stdout:
                line = raw_line.decode("utf-8", errors="replace")
                chunks.append(line)
                await ws.send_json({"type": "tool_output", "content": line})

        try:
            await asyncio.wait_for(asyncio.gather(_drain(), proc.wait()), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            msg = f"\n[TIMEOUT — command killed after {timeout}s]\n"
            chunks.append(msg)
            await ws.send_json({"type": "tool_output", "content": msg})

        return "".join(chunks) or "(no output)"
    except Exception as exc:
        msg = f"[bash error: {exc}]\n"
        await ws.send_json({"type": "tool_output", "content": msg})
        return msg


async def _exec_read_file(path: str) -> str:
    try:
        p = Path(path).expanduser()
        if not p.exists():
            return f"[read_file error: not found — {path}]"
        if p.stat().st_size > 10 * 1024 * 1024:
            return f"[read_file error: file too large ({p.stat().st_size} bytes)]"
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return f"[read_file error: {exc}]"


async def _exec_write_file(path: str, content: str, mode: str = "write") -> str:
    try:
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8") if mode != "append" else \
            open(p, "a", encoding="utf-8").write(content)
        return f"Written {len(content)} chars to {p}"
    except Exception as exc:
        return f"[write_file error: {exc}]"


# ── Claude Code CLI mode (no API key needed) ───────────────────────────────────
async def _run_claude_cli(ws: WebSocket, session_id: str) -> None:
    """Use the installed claude CLI binary — works with existing claude.ai login."""
    conversation = _sessions.get(session_id, [])
    if not conversation:
        return

    # Build prompt: system instructions + conversation history
    system_block = (
        "You are PROMET, an expert Android security researcher.\n"
        "Follow the phased workflow in AGENTS.md and WORKFLOW.md in your working directory.\n"
        "Use bash tool to run real commands on this machine. Never mock or simulate output.\n"
        "Announce each phase you enter, e.g. '## Phase 3: Static Triage'.\n"
        "Write findings to workspace incrementally.\n\n"
    )

    history_lines = []
    for m in conversation[:-1]:
        role = "User" if m["role"] == "user" else "Assistant"
        body = m["content"] if isinstance(m["content"], str) else json.dumps(m["content"])
        history_lines.append(f"{role}: {body}")

    last_msg = conversation[-1]["content"] if conversation else ""
    sep = "\n---\n" if history_lines else ""
    full_prompt = system_block + "\n".join(history_lines) + sep + f"User: {last_msg}"

    cmd = [
        CLAUDE_BIN,
        "--print",
        "--dangerously-skip-permissions",
        "--allowedTools", "Bash,Read,Write,Edit,Glob,Grep",
        full_prompt,
    ]

    try:
        await ws.send_json({"type": "tool_start", "id": "cli-session", "name": "claude-cli"})
        await ws.send_json({"type": "tool_exec",  "id": "cli-session", "name": "claude-cli",
                            "input": {"command": f"claude --print [prompt {len(full_prompt)} chars]"}})

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(PROMPTS_DIR),
        )

        chunks: list[str] = []
        phase_sent: set[int] = set()

        async def _drain():
            async for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace")
                chunks.append(line)
                await ws.send_json({"type": "tool_output", "content": line})
                phase = _detect_phase(line)
                if phase is not None and phase not in phase_sent:
                    phase_sent.add(phase)
                    await ws.send_json({"type": "phase", "number": phase})

        try:
            await asyncio.wait_for(asyncio.gather(_drain(), proc.wait()), timeout=600)
        except asyncio.TimeoutError:
            proc.kill()
            await ws.send_json({"type": "tool_output", "content": "\n[Session timeout — 10 minutes]\n"})

        full_response = "".join(chunks)
        conversation.append({"role": "assistant", "content": full_response})
        _sessions[session_id] = conversation

        await ws.send_json({"type": "tool_result", "id": "cli-session", "name": "claude-cli"})
        await ws.send_json({"type": "done"})

    except FileNotFoundError:
        await ws.send_json({
            "type": "error",
            "message": (
                f"Claude Code CLI not found at '{CLAUDE_BIN}'.\n"
                "Install Claude Code: npm install -g @anthropic-ai/claude-code\n"
                "Or add an Anthropic API key in ⚙ Settings."
            ),
        })
    except Exception as exc:
        await ws.send_json({"type": "error", "message": f"CLI error: {exc}"})


# ── Claude API mode (requires API key) ────────────────────────────────────────
async def _run_claude_api(ws: WebSocket, session_id: str) -> None:
    """Use Anthropic SDK with streaming and tool use — requires API key."""

    conversation = _sessions.setdefault(session_id, [])

    while True:
        # ── Stream one assistant turn ──────────────────────────────────────────
        tool_starts: dict[int, dict] = {}   # block_index → {id, name}
        phase_sent: set[int] = set()

        try:
            async with _client.messages.stream(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                messages=conversation,
                tools=TOOLS,
            ) as stream:
                async for event in stream:
                    etype = event.type

                    if etype == "content_block_start":
                        cb = event.content_block
                        if cb.type == "tool_use":
                            tool_starts[event.index] = {"id": cb.id, "name": cb.name}
                            await ws.send_json({
                                "type": "tool_start",
                                "id": cb.id,
                                "name": cb.name,
                            })

                    elif etype == "content_block_delta":
                        delta = event.delta
                        if delta.type == "text_delta":
                            text = delta.text
                            await ws.send_json({"type": "text", "content": text})
                            phase = _detect_phase(text)
                            if phase is not None and phase not in phase_sent:
                                phase_sent.add(phase)
                                await ws.send_json({"type": "phase", "number": phase})

                # Finalise message
                final = await stream.get_final_message()

        except anthropic.APIStatusError as exc:
            await ws.send_json({"type": "error", "message": f"Claude API error {exc.status_code}: {exc.message}"})
            return
        except Exception as exc:
            await ws.send_json({"type": "error", "message": f"Streaming error: {exc}"})
            return

        # Persist assistant turn
        conversation.append({"role": "assistant", "content": final.content})
        _sessions[session_id] = conversation

        # ── Handle tool calls ──────────────────────────────────────────────────
        tool_calls = [b for b in final.content if b.type == "tool_use"]

        if not tool_calls:
            await ws.send_json({"type": "done"})
            return

        tool_results = []
        for tc in tool_calls:
            inp = tc.input
            await ws.send_json({
                "type": "tool_exec",
                "id": tc.id,
                "name": tc.name,
                "input": inp,
            })

            if tc.name == "bash":
                result = await _exec_bash(ws, inp.get("command", ""), inp.get("timeout", 120))
            elif tc.name == "read_file":
                result = await _exec_read_file(inp.get("path", ""))
            elif tc.name == "write_file":
                result = await _exec_write_file(inp.get("path", ""), inp.get("content", ""), inp.get("mode", "write"))
            else:
                result = f"[unknown tool: {tc.name}]"

            await ws.send_json({"type": "tool_result", "id": tc.id, "name": tc.name})
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tc.id,
                "content": result[:60_000],
            })

        # Append tool results and loop back
        conversation.append({"role": "user", "content": tool_results})
        _sessions[session_id] = conversation


# ── Router: picks API mode or CLI mode automatically ──────────────────────────
async def _run_claude(ws: WebSocket, session_id: str) -> None:
    if _client:
        await _run_claude_api(ws, session_id)
    else:
        await _run_claude_cli(ws, session_id)


# ── FastAPI app ────────────────────────────────────────────────────────────────
app = FastAPI(title="PROMET Web UI")

_static = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_static)), name="static")


@app.get("/")
async def root() -> HTMLResponse:
    return HTMLResponse((Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8"))


@app.get("/api/config")
async def api_get_config():
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    cli_found = bool(shutil.which(CLAUDE_BIN) or Path(CLAUDE_BIN).exists())
    return {
        "has_api_key": has_key,
        "mode": "api" if has_key else ("cli" if cli_found else "none"),
        "claude_bin": CLAUDE_BIN,
        "cli_found": cli_found,
        "model": MODEL,
        "shell": SHELL,
        "platform": sys.platform,
    }


@app.post("/api/config")
async def api_set_config(data: dict):
    global _client, CLAUDE_BIN
    env_path = Path(__file__).parent / ".env"

    # Load existing .env lines (preserve other keys)
    env_lines: dict[str, str] = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env_lines[k.strip()] = v.strip()

    key = data.get("api_key", "").strip()
    if key:
        os.environ["ANTHROPIC_API_KEY"] = key
        _client = anthropic.AsyncAnthropic(api_key=key)
        env_lines["ANTHROPIC_API_KEY"] = key

    claude_bin = data.get("claude_bin", "").strip()
    if claude_bin:
        os.environ["PROMET_CLAUDE_BIN"] = claude_bin
        CLAUDE_BIN = claude_bin
        env_lines["PROMET_CLAUDE_BIN"] = claude_bin

    env_path.write_text(
        "\n".join(f"{k}={v}" for k, v in env_lines.items()) + "\n",
        encoding="utf-8"
    )
    return {"status": "ok", "mode": "api" if _client else "cli"}


@app.post("/api/upload")
async def api_upload(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(400, "Only .apk files are allowed")
    safe = re.sub(r"[^\w\-.]", "_", file.filename)
    dest = UPLOAD_DIR / safe
    data = await file.read()
    async with aiofiles.open(dest, "wb") as fh:
        await fh.write(data)
    return {"filename": safe, "path": str(dest), "size": len(data)}


@app.websocket("/ws/{session_id}")
async def ws_endpoint(websocket: WebSocket, session_id: str) -> None:
    await websocket.accept()
    _sessions.setdefault(session_id, [])
    try:
        while True:
            data = await websocket.receive_json()
            mtype = data.get("type")

            if mtype == "chat":
                msg = data.get("message", "").strip()
                apk  = data.get("apk_path")
                if not msg and not apk:
                    continue
                full = f"{msg}\n\nAPK path on this machine: {apk}" if apk else msg
                _sessions[session_id].append({"role": "user", "content": full})
                await _run_claude(websocket, session_id)

            elif mtype == "clear":
                _sessions[session_id] = []
                await websocket.send_json({"type": "cleared"})

            elif mtype == "ping":
                await websocket.send_json({"type": "pong"})

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass


if __name__ == "__main__":
    print(f"\n  PROMET Web UI → http://localhost:{PORT}")
    print(f"  Shell   : {SHELL}")
    print(f"  Model   : {MODEL}")
    print(f"  Platform: {sys.platform}")
    print(f"  Uploads : {UPLOAD_DIR}\n")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
