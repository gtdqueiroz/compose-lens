"""Small, explicit rules. Findings describe configuration, not exploitability."""
from dataclasses import asdict, dataclass
from pathlib import Path
import yaml

MAX_BYTES = 1024 * 1024
LIMITATIONS = [
    "Static review of one file; not a security certification or full Compose validation.",
    "Does not resolve environment variables, .env files, include, extends or override files.",
    "Does not inspect images, running containers, firewall rules or actual network reachability.",
    "Unresolved values may prevent rules from detecting a configuration; review them manually.",
]


class InputError(ValueError):
    pass


class UniqueLoader(yaml.SafeLoader):
    """Reject ambiguous YAML keys, but support standard YAML merge mappings."""
    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in seen:
                    raise InputError("Duplicate YAML key; remove the ambiguous entry.")
                seen.add(key)
            except TypeError as exc:
                raise InputError("YAML mapping keys must be scalar values.") from exc
        return super().construct_mapping(node, deep=deep)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    service: str
    field: str
    title: str
    explanation: str
    recommendation: str

    def to_dict(self):
        return asdict(self)


def load_compose(path):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise InputError("Input exceeds the 1 MiB limit.")
        document = yaml.load(data.decode("utf-8"), Loader=UniqueLoader)
    except (OSError, UnicodeError, yaml.YAMLError, RecursionError, ValueError) as exc:
        if isinstance(exc, InputError):
            raise
        # Parser exceptions can contain the original line, including a secret.
        raise InputError("Cannot read input as valid UTF-8 Compose YAML. Check the file and syntax.") from exc
    validate(document)
    return document


def validate(document):
    if not isinstance(document, dict):
        raise InputError("Expected a YAML mapping containing services.")
    services = document.get("services")
    if not isinstance(services, dict) or not services:
        raise InputError("services must be a non-empty mapping.")
    for name, service in services.items():
        if not isinstance(name, str) or not isinstance(service, dict):
            raise InputError("Each service must have a text name and a configuration mapping.")
        for field in ("volumes", "ports", "cap_add"):
            if field in service and not isinstance(service[field], list):
                raise InputError(f"{field} must be a list.")
        for field in ("network_mode", "pid", "user"):
            if field in service and (isinstance(service[field], (dict, list, bool)) or service[field] is None):
                raise InputError(f"{field} must be a string or number.")
        if "privileged" in service and not isinstance(service["privileged"], bool):
            raise InputError("privileged must be a YAML boolean (true or false).")
        if any(not isinstance(cap, str) for cap in service.get("cap_add", [])):
            raise InputError("cap_add entries must be strings.")
        for field in ("volumes", "ports"):
            if any(isinstance(entry, bool) or not isinstance(entry, (str, int, dict)) for entry in service.get(field, [])):
                raise InputError(f"Unsupported entry in {field}.")


def volume_parts(entry):
    if isinstance(entry, dict):
        source, target = entry.get("source", ""), entry.get("target", "")
        return str(source), str(target), entry.get("type") == "bind"
    text = str(entry)
    # Split from the right to preserve drive letters in Windows bind paths.
    parts = text.rsplit(":", 2)
    if len(parts) == 1:
        return "", parts[0], False
    if len(parts) == 3 and parts[-1].startswith(("/", "\\")):
        source, target = ":".join(parts[:-1]), parts[-1]
    else:
        source, target = parts[0], parts[1]
    return source, target, source.startswith(("/", ".", "~")) or (len(source) > 1 and source[1] == ":")


def published_scope(entry):
    """None means no host publication; otherwise return declared bind scope."""
    if isinstance(entry, dict):
        host = str(entry.get("host_ip", ""))
    else:
        text = str(entry).split("/", 1)[0]
        host = text.rsplit(":", 2)[0] if text.count(":") >= 2 else ""
    host = host.strip("[]")
    if host == "::1" or host.startswith("127."):
        return "loopback"
    if host in ("", "0.0.0.0", "::"):
        return "all interfaces by default"
    return "an explicit or unresolved host address"


def audit(document):
    validate(document)
    findings = []
    for name, service in document["services"].items():
        def add(rule, severity, field, title, explanation, recommendation):
            findings.append(Finding(rule, severity, name, field, title, explanation, recommendation))

        if service.get("privileged") is True:
            add("CL001", "high", "privileged", "Privileged container",
                "Privileged mode grants broad host capabilities and device access.",
                "Remove privileged mode if possible; grant only the devices and capabilities required.")
        if service.get("network_mode") == "host":
            add("CL002", "medium", "network_mode", "Host network namespace",
                "Host networking reduces network isolation on supported platforms; behavior depends on the runtime.",
                "Prefer a bridge network and explicit port publication unless host networking is necessary.")
        if service.get("pid") == "host":
            add("CL003", "high", "pid", "Host process namespace",
                "The service shares the host PID namespace, reducing process isolation.",
                "Remove pid: host unless explicitly required and reviewed.")
        caps = {cap.upper().removeprefix("CAP_") for cap in service.get("cap_add", [])}
        if caps.intersection({"ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN"}):
            add("CL004", "medium", "cap_add", "Powerful capabilities added",
                "The service adds broad capabilities that expand its privileges within the relevant namespaces.",
                "Review each added capability and retain only those needed by the application.")
        for index, volume in enumerate(service.get("volumes", [])):
            source, target, bind = volume_parts(volume)
            if any(path.replace("\\", "/").rstrip("/").endswith("/docker.sock") for path in (source, target)):
                add("CL005", "high", f"volumes[{index}]", "Docker socket mount",
                    "Access to a Docker daemon socket can permit control over containers and potentially the host. A read-only mount does not make the daemon API read-only.",
                    "Avoid direct socket access; if required, review daemon privileges and use a narrowly scoped access mechanism.")
            if bind and source and source.rstrip("/") == "":
                add("CL006", "high", f"volumes[{index}]", "Host root filesystem mount",
                    "Mounting the host root exposes a broad set of host files, including with read-only access.",
                    "Mount only the specific directory needed, read-only where appropriate.")
        if "user" in service and str(service["user"]).split(":", 1)[0] in ("0", "root"):
            add("CL007", "medium", "user", "Explicit root user",
                "The configuration explicitly selects root inside the container. Host impact depends on namespaces and runtime configuration.",
                "Use a suitable non-root UID where supported, and review file permissions.")
        for index, port in enumerate(service.get("ports", [])):
            scope = published_scope(port)
            if scope is not None and scope != "loopback":
                add("CL008", "info", f"ports[{index}]", "Host port publication",
                    f"A port is published on {scope}. This can be intentional and does not prove Internet reachability.",
                    "Check the intended audience, firewall and bind address; use loopback when only local access is needed.")
    return findings
