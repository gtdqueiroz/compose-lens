# Compose Lens

An explainable, offline Docker Compose configuration reviewer for people learning self-hosting and container security.

Compose Lens reads a YAML file and produces contextual findings: what was detected, why it matters, and what to review. It does not contact Docker, start containers, scan networks, modify the input or use an AI API.

**Status:** working v0.1 prototype, developed with AI assistance. Eight explicit rules, text and JSON reports, and automated tests. Not a production security scanner.

## Quick start

Requires Python 3.10+; Docker is not required.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
compose-lens examples/review-needed.yaml --fail-on none
compose-lens examples/reduced-exposure.yaml
```

On Windows, use `.venv\Scripts\activate` instead. You can also run `python -m compose_lens` from the project directory once PyYAML is installed.

The intentionally overprivileged fixture uses placeholder image names. It is an input for analysis, not something to deploy.

## Example output

```text
Compose Lens | static configuration review
high: 4 | medium: 3 | info: 1

[HIGH] CL001 "demo" / privileged: Privileged container
  Why: Privileged mode grants broad host capabilities and device access.
  Review: Remove privileged mode if possible; grant only the devices and capabilities required.
```

The complete output includes all findings and a limitations section.

## JSON and automation

```bash
compose-lens examples/review-needed.yaml --format json --fail-on none > report.json
compose-lens compose.yaml --fail-on medium
```

Exit codes: **0** means no findings meet the selected threshold; **1** means at least one finding meets it; **2** means invalid input or command usage. The default threshold is `high`. `--fail-on none` disables failure on findings, but does not suppress input errors. JSON reports include `schema_version`, severity counts, findings and limitations.

## Rules

| ID | Default severity | Configuration |
| --- | --- | --- |
| CL001 | High | `privileged: true` |
| CL002 | Medium | Host networking |
| CL003 | High | Host PID namespace |
| CL004 | Medium | Added `ALL`, `SYS_ADMIN`, `SYS_PTRACE` or `NET_ADMIN` capabilities |
| CL005 | High | Mount whose source or target ends in `/docker.sock` |
| CL006 | High | Bind mount of the host root filesystem `/` |
| CL007 | Medium | Explicit root user, including `0:0` |
| CL008 | Info | Host port publication without an explicit loopback address |

Severity is a review priority chosen for this prototype, not a CVSS score or a claim of exploitability. A public-facing web service may legitimately publish a port. An omitted `user` is not flagged as root because this tool does not inspect the image's default user. Socket detection is a path heuristic; renamed sockets and other daemon access mechanisms are outside this version's coverage.

## Scope and limitations

- Reviews a single YAML document, up to 1 MiB; rejects duplicate explicit keys and unsafe Python YAML tags. Standard YAML merge mappings are supported.
- Does not resolve environment interpolation, `.env`, `include`, `extends` or override files. Unresolved settings can cause missed findings. This is not a complete Compose parser or schema validator.
- Checks common short and long port/mount forms. Does not promise complete Windows path or Compose syntax coverage.
- Does not inspect images, vulnerabilities, runtime users, firewall policies, rootless settings or actual reachability.
- Does not automatically fix configurations. No findings does **not** mean secure.
- Reports contain service names and field locations, not raw environment values or file contents. Treat reports as potentially sensitive infrastructure metadata.

## Development

```bash
python -m unittest discover -s tests -v
```

Tests use the standard library; PyYAML is the only runtime dependency. Run tests from the repository root.

```text
compose_lens/audit.py   Input loading, basic validation, finding model and rules
compose_lens/cli.py     Arguments, output formats and exit codes
examples/              Synthetic analysis fixtures
tests/                 Rule, input and CLI regression tests
```

## Next milestones

1. Expand input validation and report unsupported or unresolved settings explicitly.
2. Add an HTML report with escaped content and rule documentation links.
3. Support per-rule exclusions with a written justification.
4. Add CI and broader Compose syntax fixtures.
5. Investigate safe handling of merged Compose configurations without leaking resolved secrets.

These are planned features, not implemented capabilities.

## Design references

- [Docker Compose service reference](https://docs.docker.com/reference/compose-file/services/)
- [Docker Engine security](https://docs.docker.com/engine/security/)
- [Bind mounts](https://docs.docker.com/engine/storage/bind-mounts/)

## License

MIT. See LICENSE. Initial implementation and documentation were created with AI assistance; human review and further development are part of the project workflow.
