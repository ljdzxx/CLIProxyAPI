import base64
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


APP = "lj-cpa-syd"
CMD = "fly-ljdzxx"

OUT_DIR = Path(r"C:\Users\ray\Documents\JuCodex\fly.io.auths")
OUT_DIR.mkdir(parents=True, exist_ok=True)

OUT_STDOUT = OUT_DIR / f"{APP}.stdout.txt"
OUT_STDERR = OUT_DIR / f"{APP}.stderr.txt"
OUT_B64 = OUT_DIR / f"{APP}.b64.txt"
OUT_TGZ = OUT_DIR / f"{APP}.tar.gz"

REMOTE_CMD = 'sh -c "tar czf - -C /data .cli-proxy-api | base64"'


def run_fly_command(cmd: str, app: str, remote_cmd: str) -> tuple[str, str, int]:
    exe_path = shutil.which(cmd)

    if exe_path:
        result = subprocess.run(
            [
                exe_path,
                "ssh",
                "console",
                "-a",
                app,
                "-C",
                remote_cmd,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout, result.stderr, result.returncode

    powershell_exe = shutil.which("pwsh") or shutil.which("powershell")
    if not powershell_exe:
        raise FileNotFoundError("pwsh/powershell not found")

    ps_script = f"""
$ErrorActionPreference = "Stop"

# 手动加载 PowerShell profile，确保 fly-ljdzxx 这个 function 可用
$profiles = @(
    $PROFILE.AllUsersAllHosts,
    $PROFILE.AllUsersCurrentHost,
    $PROFILE.CurrentUserAllHosts,
    $PROFILE.CurrentUserCurrentHost
)

foreach ($p in $profiles) {{
    if ($p -and (Test-Path $p)) {{
        . $p
    }}
}}

$cmdName = "{cmd}"
$appName = "{app}"
$remoteCmd = @'
{remote_cmd}
'@

& $cmdName ssh console -a $appName -C $remoteCmd
"""

    with tempfile.NamedTemporaryFile(
        "w",
        suffix=".ps1",
        delete=False,
        encoding="utf-8",
    ) as f:
        f.write(ps_script)
        script_path = f.name

    result = subprocess.run(
        [
            powershell_exe,
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script_path,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    return result.stdout, result.stderr, result.returncode


def extract_base64_payload(raw: str) -> str:
    """
    只保留看起来像 base64 的行，避免 flyctl 的 Connecting/Warning/Usage 等文本混进去。
    """
    lines = []

    for line in raw.splitlines():
        s = line.strip()

        if not s:
            continue

        if re.fullmatch(r"[A-Za-z0-9+/=]+", s):
            lines.append(s)

    return "".join(lines)


def main() -> None:
    stdout, stderr, returncode = run_fly_command(CMD, APP, REMOTE_CMD)

    OUT_STDOUT.write_text(stdout, encoding="utf-8", errors="replace")
    OUT_STDERR.write_text(stderr, encoding="utf-8", errors="replace")

    if returncode != 0:
        print("command failed")
        print("stdout:", OUT_STDOUT)
        print("stderr:", OUT_STDERR)
        raise RuntimeError(f"command failed, see: {OUT_STDERR}")

    b64 = extract_base64_payload(stdout)
    OUT_B64.write_text(b64, encoding="utf-8")

    print(f"base64 length: {len(b64)}")

    if not b64:
        raise RuntimeError(
            f"没有提取到 base64 内容，请检查：\n"
            f"stdout: {OUT_STDOUT}\n"
            f"stderr: {OUT_STDERR}"
        )

    data = base64.b64decode(b64)
    OUT_TGZ.write_bytes(data)

    print(f"saved base64: {OUT_B64}")
    print(f"saved archive: {OUT_TGZ}")


if __name__ == "__main__":
    main()