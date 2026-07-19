from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_SOURCE = REPO_ROOT / "scripts" / "install_local.sh"
ENV_TEMPLATE_SOURCE = REPO_ROOT / "config" / "server-gateway.env.example"
PYPROJECT_SOURCE = REPO_ROOT / "pyproject.toml"


class InstallLocalScriptTests(unittest.TestCase):
    def test_reuses_env_fills_missing_secrets_and_starts_user_service(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_root = Path(tempdir)
            project_root = temp_root / "project"
            home_dir = temp_root / "home"
            fake_bin = temp_root / "bin"
            log_path = temp_root / "commands.log"

            (project_root / "scripts").mkdir(parents=True)
            (project_root / "config").mkdir(parents=True)
            (project_root / "src" / "server_gateway").mkdir(parents=True)
            home_dir.mkdir()
            fake_bin.mkdir()

            (project_root / "scripts" / "install_local.sh").write_text(
                SCRIPT_SOURCE.read_text()
            )
            (project_root / "config" / "server-gateway.env.example").write_text(
                ENV_TEMPLATE_SOURCE.read_text()
            )
            (project_root / "pyproject.toml").write_text(PYPROJECT_SOURCE.read_text())
            (project_root / "src" / "server_gateway" / "__init__.py").write_text(
                "__version__ = '0.1.0'\n"
            )

            (project_root / ".env").write_text(
                "\n".join(
                    [
                        "SERVER_GATEWAY_HOST=127.0.0.1",
                        "SERVER_GATEWAY_PORT=8787",
                        "SERVER_GATEWAY_AUTH_MODE=either",
                        "SERVER_GATEWAY_BEARER_TOKEN=replace-me",
                        "SERVER_GATEWAY_HMAC_KEYS=default:replace-me",
                        "SERVER_GATEWAY_ALLOWED_IPS=10.0.0.0/8",
                        "SERVER_GATEWAY_SERVICE_NAME=custom-name",
                        "",
                    ]
                )
            )

            self._write_stub(
                fake_bin / "uv",
                f"""#!/usr/bin/env bash
set -euo pipefail
echo "uv:$*" >> "{log_path}"
if [[ "${{1-}}" == "sync" ]]; then
  mkdir -p .venv/bin
  printf '#!/usr/bin/env bash\\nexit 0\\n' > .venv/bin/python
  chmod +x .venv/bin/python
fi
""",
            )
            self._write_stub(
                fake_bin / "systemctl",
                f"""#!/usr/bin/env bash
set -euo pipefail
echo "systemctl:$*" >> "{log_path}"
""",
            )
            self._write_stub(
                fake_bin / "loginctl",
                f"""#!/usr/bin/env bash
set -euo pipefail
echo "loginctl:$*" >> "{log_path}"
""",
            )

            subprocess.run(
                ["bash", "scripts/install_local.sh"],
                cwd=project_root,
                env={
                    **os.environ,
                    "HOME": str(home_dir),
                    "PATH": f"{fake_bin}:{os.environ['PATH']}",
                },
                check=True,
            )

            env_text = (project_root / ".env").read_text()
            unit_text = (
                home_dir / ".config" / "systemd" / "user" / "server-gateway.service"
            ).read_text()
            log_text = log_path.read_text()

            self.assertIn("SERVER_GATEWAY_SERVICE_NAME=custom-name", env_text)
            self.assertNotIn("SERVER_GATEWAY_BEARER_TOKEN=replace-me", env_text)
            self.assertNotIn("SERVER_GATEWAY_HMAC_KEYS=default:replace-me", env_text)
            self.assertRegex(env_text, r"SERVER_GATEWAY_BEARER_TOKEN=\S+")
            self.assertRegex(env_text, r"SERVER_GATEWAY_HMAC_KEYS=default:\S+")
            self.assertIn(f"WorkingDirectory={project_root}", unit_text)
            self.assertIn(f"EnvironmentFile={project_root / '.env'}", unit_text)
            self.assertIn("uv:sync", log_text)
            self.assertIn("loginctl:enable-linger", log_text)
            self.assertIn("systemctl:--user daemon-reload", log_text)
            self.assertIn(
                "systemctl:--user enable --now server-gateway.service", log_text
            )

    def test_ignores_invalid_lines_when_loading_env_for_systemd(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_root = Path(tempdir)
            project_root = temp_root / "project"
            home_dir = temp_root / "home"
            fake_bin = temp_root / "bin"
            log_path = temp_root / "commands.log"

            (project_root / "scripts").mkdir(parents=True)
            (project_root / "config").mkdir(parents=True)
            (project_root / "src" / "server_gateway").mkdir(parents=True)
            home_dir.mkdir()
            fake_bin.mkdir()

            (project_root / "scripts" / "install_local.sh").write_text(
                SCRIPT_SOURCE.read_text()
            )
            (project_root / "config" / "server-gateway.env.example").write_text(
                ENV_TEMPLATE_SOURCE.read_text()
            )
            (project_root / "pyproject.toml").write_text(PYPROJECT_SOURCE.read_text())
            (project_root / "src" / "server_gateway" / "__init__.py").write_text(
                "__version__ = '0.1.0'\n"
            )

            (project_root / ".env").write_text(
                "\n".join(
                    [
                        "SERVER_GATEWAY_HOST=127.0.0.1",
                        "SERVER_GATEWAY_PORT=8787",
                        "SERVER_GATEWAY_AUTH_MODE=hmac",
                        "SERVER_GATEWAY_HMAC_KEYS=default:test-key",
                        "LEGACY_NAME=still-kept",
                        "~",
                        "",
                    ]
                )
            )

            self._write_stub(
                fake_bin / "uv",
                f"""#!/usr/bin/env bash
set -euo pipefail
echo "uv:$*" >> "{log_path}"
if [[ "${{1-}}" == "sync" ]]; then
  mkdir -p .venv/bin
  printf '#!/usr/bin/env bash\\nexit 0\\n' > .venv/bin/python
  chmod +x .venv/bin/python
fi
""",
            )
            self._write_stub(
                fake_bin / "systemctl",
                f"""#!/usr/bin/env bash
set -euo pipefail
echo "systemctl:$*" >> "{log_path}"
""",
            )
            self._write_stub(
                fake_bin / "loginctl",
                f"""#!/usr/bin/env bash
set -euo pipefail
echo "loginctl:$*" >> "{log_path}"
""",
            )

            subprocess.run(
                ["bash", "scripts/install_local.sh"],
                cwd=project_root,
                env={
                    **os.environ,
                    "HOME": str(home_dir),
                    "PATH": f"{fake_bin}:{os.environ['PATH']}",
                },
                check=True,
            )

            runtime_env_path = project_root / ".env.runtime"
            unit_text = (
                home_dir / ".config" / "systemd" / "user" / "server-gateway.service"
            ).read_text()

            self.assertTrue(runtime_env_path.exists())
            self.assertIn(f"EnvironmentFile={runtime_env_path}", unit_text)
            self.assertNotIn("\n~\n", runtime_env_path.read_text())

    def _write_stub(self, path: Path, contents: str) -> None:
        path.write_text(contents)
        path.chmod(path.stat().st_mode | stat.S_IEXEC)


if __name__ == "__main__":
    unittest.main()
