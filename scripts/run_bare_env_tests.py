#!/usr/bin/env python3
"""在隐藏可选依赖(PyYAML、openpyxl)的裸环境下跑完整测试套件。

为什么需要它:插件对 PyYAML / openpyxl 是"可选依赖,缺了走 stdlib fallback"。
但平时开发机都装着这两个库,测试只能证明"装了能用",证明不了"没装也能用"。
历史上 1.0.x→1.1.1 多次回归(没装 PyYAML 就崩、xlsx 不退化)正是因为发布前
从没在缺依赖的环境真跑过一遍。

这个脚本临时屏蔽这些模块(让 import 抛 ModuleNotFoundError,与真机缺库时
CPython 的行为完全一致),再跑全套 test_*.py。只要有 fallback 没接住,就会红。

用法:
    python3 scripts/run_bare_env_tests.py
退出码 0 表示裸环境下全部通过(允许 skip);非 0 表示有 fallback 失效。
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 要在裸环境里隐藏的可选依赖。新增可选依赖时同步加进来。
BLOCKED = ("yaml", "openpyxl")

# 写入临时目录的 sitecustomize.py:Python 启动时会自动 import 它(只要它在
# sys.path 上),从而在最早时机挂上 import 钩子。抛 ModuleNotFoundError 而非
# ImportError,是为了忠实复刻真机缺库的行为——产品代码的 fallback 普遍写的是
# `except ModuleNotFoundError`,用父类 ImportError 会造成假阳性。
SHIM_TEMPLATE = '''import builtins as _builtins

_blocked = {blocked!r}
_real_import = _builtins.__import__


def _guard(name, *args, **kwargs):
    top = name.split(".")[0]
    if top in _blocked:
        raise ModuleNotFoundError(
            "No module named %r (hidden by bare-env shim)" % top, name=top
        )
    return _real_import(name, *args, **kwargs)


_builtins.__import__ = _guard
'''


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cloversec-bareenv-") as tmp:
        shim_dir = Path(tmp)
        (shim_dir / "sitecustomize.py").write_text(
            SHIM_TEMPLATE.format(blocked=set(BLOCKED)), encoding="utf-8"
        )

        env = dict(os.environ)
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            str(shim_dir) + (os.pathsep + existing if existing else "")
        )

        print(f"[bare-env] hiding optional deps: {', '.join(BLOCKED)}")

        # 防呆:先确认 shim 真的拦住了,否则这次"裸环境测试"是假的。
        for module in BLOCKED:
            probe = subprocess.run(
                [sys.executable, "-c", f"import {module}"],
                env=env,
                capture_output=True,
            )
            if probe.returncode == 0:
                print(
                    f"[bare-env] ERROR: shim failed to hide '{module}'; "
                    "aborting so we don't report a false pass.",
                    file=sys.stderr,
                )
                return 1
        print("[bare-env] shim verified — optional deps are hidden")

        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
            cwd=ROOT,
            env=env,
        )
        if proc.returncode == 0:
            print("[bare-env] PASS — all fallbacks held without optional deps")
        else:
            print(
                "[bare-env] FAIL — something broke when optional deps were missing",
                file=sys.stderr,
            )
        return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
