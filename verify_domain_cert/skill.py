# -*- encoding: utf-8 -*-
"""Install a portable Agent Skill for verify_domain_cert.

The generated ``SKILL.md`` follows the Agent Skills specification
(https://agentskills.io/specification), so agents such as Pi, Claude Code and
other compatible harnesses can discover and use the certificate checker.
"""

from __future__ import annotations

import argparse
from pathlib import Path

SKILL_NAME = "verify-domain-cert"

SKILL_MD = '''---
name: verify-domain-cert
description: Check TLS/SSL certificates for one or more domains: expiry dates, SAN/CN names, issuer and handshake result. Use when asked whether a website certificate is valid, expired or about to expire, or whether it matches the requested hostname.
license: MIT
compatibility: Requires Python 3.11+ and the verify_domain_cert package (`pip install verify_domain_cert`).
---

# Verify domain certificates

## Check one or more domains

Run the CLI with absolute URLs. Multiple hosts are checked in parallel:

```bash
verify_domain_cert https://www.google.com https://www.baidu.com
```

Each host prints a block such as:

```text
» www.google.com « ... ('142.250.72.164', 443)
        commonName: www.google.com
        SAN: ('www.google.com',)
        issuer: WR2
        notBefore: 2026-10-14 08:35:00+00:00
        notAfter:  2027-01-06 08:34:59+00:00
```

Read `notAfter` to answer expiry questions; compare it with the current date
and report how many days remain. Report the SAN/CN and issuer when asked about
hostname matching or certificate authority.

## Use the Python API

```python
from verify_domain_cert.check import get_certificate, get_alt_names, get_common_name, get_issuer

host = get_certificate("www.google.com")
print(host.cert.not_valid_after_utc)
print(get_alt_names(host.cert), get_issuer(host.cert))
```

Notes:

- Input must include a scheme when using the CLI (`https://example.com`); a
  bare host name is accepted by the Python API.
- Non-standard ports are supported, e.g. `https://example.com:8443`.
- If the handshake fails, the certificate is not retrievable: report the
  verification as failed instead of guessing an expiry date.
'''

def default_skill_dir() -> Path:
    """Default portable Agent Skills location under the user's home directory."""
    return Path.home() / ".agents" / "skills" / SKILL_NAME


def install_skill(target_dir: Path | str | None = None, force: bool = False) -> Path:
    """Write ``SKILL.md`` into *target_dir* and return the written file path.

    ``target_dir`` is the skill directory itself (the one that will contain
    ``SKILL.md``). When omitted, ``~/.agents/skills/verify-domain-cert`` is used.
    """
    skill_dir = Path(target_dir).expanduser() if target_dir else default_skill_dir()
    skill_file = skill_dir / "SKILL.md"

    if skill_dir.exists() and not skill_dir.is_dir():
        raise NotADirectoryError(f"{skill_dir} exists and is not a directory")
    if skill_file.exists() and not force:
        raise FileExistsError(
            f"{skill_file} already exists; pass force=True (CLI: --force) to overwrite"
        )

    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_file.write_text(SKILL_MD, encoding="utf-8")
    return skill_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Write the verify_domain_cert Agent Skill (SKILL.md) into an agent skills directory"
    )
    parser.add_argument(
        "--dir",
        dest="target_dir",
        default=None,
        help=f"skill directory to write (default: {default_skill_dir()})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing SKILL.md",
    )
    args = parser.parse_args(argv)

    try:
        skill_file = install_skill(args.target_dir, force=args.force)
    except (FileExistsError, NotADirectoryError) as exc:
        parser.exit(1, f"error: {exc}\n")
        return 1

    print(f"installed agent skill: {skill_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
