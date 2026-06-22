import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCKERIZER = ROOT / "plugins" / "cloversec-ctf-forexample" / "skills" / "cloversec-ctf-build-dockerizer"
SCRIPTS = DOCKERIZER / "scripts"


class DockerizerRegressionTests(unittest.TestCase):
    def test_python_source_integrity_findings_block_auto_render(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.py").write_text(
                "import os\n"
                "import db\n"
                "from flask import Flask, render_template\n"
                "app = Flask(__name__)\n"
                "@app.route('/')\n"
                "def index():\n"
                "    return render_template('index.html', flag=os.getenv('FLAG'))\n",
                encoding="utf-8",
            )
            (project / "users.db").write_bytes(b"sqlite")

            derive = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "derive_config.py"),
                    "--project-dir",
                    str(project),
                    "--format",
                    "json",
                    "--pretty",
                ],
                cwd=DOCKERIZER,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(derive.returncode, 0, derive.stderr)
            proposal = json.loads(derive.stdout)
            codes = {item["code"] for item in proposal["input_audit"]["findings"]}

            self.assertIn("PYTHON_LOCAL_IMPORT_MISSING", codes)
            self.assertIn("FLASK_TEMPLATE_MISSING", codes)
            self.assertIn("PYTHON_DEPENDENCY_DECLARATION_MISSING", codes)
            self.assertIn("FLASK_START_COMMAND_UNCONFIRMED", codes)
            self.assertIn("FLAG_ENV_NEEDS_PLATFORM_SYNC", codes)
            self.assertTrue(proposal["gates"]["requires_start_cmd_confirm"])
            self.assertGreaterEqual(proposal["blocking_source_findings_count"], 5)

            auto_render = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "workflow.py"),
                    "auto-render",
                    "--project-dir",
                    str(project),
                    "--format",
                    "json",
                ],
                cwd=DOCKERIZER,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(auto_render.returncode, 0)
            self.assertFalse((project / "Dockerfile").exists())
            self.assertIn("AUTO_RENDER_BLOCKED", auto_render.stdout)

    def test_render_outputs_lf_and_changeflag_accepts_all_dynamic_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.py").write_text("print('ok')\n", encoding="utf-8")
            (project / "challenge.yaml").write_text(
                "challenge:\n"
                "  name: lf-render\n"
                "  stack: python\n"
                "  base_image: python:3.11-slim\n"
                "  workdir: /app\n"
                "  app_src: .\n"
                "  app_dst: /app\n"
                "  expose_ports:\n"
                "    - '5000'\n"
                "  start:\n"
                "    mode: cmd\n"
                "    cmd: python app.py\n"
                "  runtime_deps: []\n"
                "  build_deps: []\n"
                "  flag:\n"
                "    path: /flag\n"
                "    permission: '444'\n"
                "  platform:\n"
                "    entrypoint: /start.sh\n"
                "    require_bash: true\n",
                encoding="utf-8",
            )

            render = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "render.py"),
                    "--config",
                    str(project / "challenge.yaml"),
                    "--output",
                    str(project),
                    "--manual",
                    "--reason",
                    "regression test",
                ],
                cwd=DOCKERIZER,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(render.returncode, 0, render.stderr)
            for name in ["Dockerfile", "start.sh", "changeflag.sh", "flag"]:
                self.assertNotIn(b"\r", (project / name).read_bytes(), name)

            validate = subprocess.run(
                [
                    "bash",
                    str(SCRIPTS / "validate.sh"),
                    "--with-dynamic-flag",
                    str(project / "Dockerfile"),
                    str(project / "start.sh"),
                    str(project / "challenge.yaml"),
                ],
                cwd=DOCKERIZER,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(validate.returncode, 0, validate.stdout + validate.stderr)
            self.assertIn("动态 flag 写入测试通过：arg", validate.stdout)
            self.assertIn("动态 flag 写入测试通过：FLAG", validate.stdout)
            self.assertIn("动态 flag 写入测试通过：CTF_FLAG", validate.stdout)

    def test_validate_reports_crlf_and_bad_changeflag_parameter_expansion(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "Dockerfile").write_text(
                "FROM python:3.11-slim\n"
                "COPY start.sh /start.sh\n"
                "COPY changeflag.sh /changeflag.sh\n"
                "COPY flag /flag\n"
                "RUN chmod 555 /start.sh /changeflag.sh && chmod 444 /flag\n"
                "EXPOSE 5000\n"
                "CMD [\"/start.sh\"]\n",
                encoding="utf-8",
            )
            (project / "start.sh").write_bytes(
                b"#!/bin/bash\r\nset -euo pipefail\r\nexec python -m http.server 5000 --bind 0.0.0.0\r\n"
            )
            (project / "changeflag.sh").write_text(
                "#!/bin/bash\n"
                "set -euo pipefail\n"
                "TARGET_PATH=\"${FLAG_PATH:-/flag}\"\n"
                "TARGET_FLAG=\"${1:-${FLAG:-flag{bad}}}\"\n"
                "printf '%s\\n' \"$TARGET_FLAG\" > \"$TARGET_PATH\"\n",
                encoding="utf-8",
            )
            (project / "flag").write_text("flag{demo}\n", encoding="utf-8")
            (project / "challenge.yaml").write_text(
                "challenge:\n"
                "  name: bad-changeflag\n"
                "  stack: python\n"
                "  workdir: /app\n"
                "  expose_ports: ['5000']\n"
                "  start:\n"
                "    mode: cmd\n"
                "    cmd: python -m http.server 5000 --bind 0.0.0.0\n"
                "  flag:\n"
                "    path: /flag\n"
                "  platform:\n"
                "    entrypoint: /start.sh\n",
                encoding="utf-8",
            )

            validate = subprocess.run(
                [
                    "bash",
                    str(SCRIPTS / "validate.sh"),
                    str(project / "Dockerfile"),
                    str(project / "start.sh"),
                    str(project / "challenge.yaml"),
                ],
                cwd=DOCKERIZER,
                text=True,
                capture_output=True,
                check=False,
            )

            combined = validate.stdout + validate.stderr
            self.assertNotEqual(validate.returncode, 0)
            self.assertIn("CRLF/Windows", combined)
            self.assertIn("嵌套参数展开", combined)


if __name__ == "__main__":
    unittest.main()
