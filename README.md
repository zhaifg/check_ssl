
## install 
```bash
pip install verify_domain_cert

```
**Prerequisite:** Python 3.11+

## usage

```bash
verify_domain_cert https://www.google.com https://www.baidu.com

```

```python

from verify_domain_cert.check import get_certificate

get_certificate("https://www.google.com")

```

## install as an agent skill

Write the bundled Agent Skill (`SKILL.md`, following the
[Agent Skills specification](https://agentskills.io/specification)) into an
agent's skills directory so assistants can check certificates for you:

```bash
# default location: ~/.agents/skills/verify-domain-cert/SKILL.md
verify_domain_cert --install-skill

# a project-local or another agent's skills directory
verify_domain_cert --install-skill --skill-dir .agents/skills/verify-domain-cert

# overwrite an existing SKILL.md
verify_domain_cert --install-skill --force
```

The same installer is available without the `verify_domain_cert` CLI, which is
handy when only the skill file is needed:

```bash
python -m verify_domain_cert.skill --dir ~/.claude/skills/verify-domain-cert
```

The installed skill tells the agent how to run the CLI, read `notAfter` from
the output, and use the Python API (`get_certificate`,
`get_alt_names`, `get_common_name`, `get_issuer`).
