import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from compose_lens.audit import InputError, audit, load_compose, volume_parts
from compose_lens.cli import main


class AuditTests(unittest.TestCase):
    def rules(self, service):
        return {f.rule_id for f in audit({"services": {"demo": service}})}

    def test_all_rules(self):
        doc = load_compose("examples/review-needed.yaml")
        self.assertEqual({f.rule_id for f in audit(doc)}, {f"CL{i:03d}" for i in range(1, 9)})

    def test_reduced_exposure(self):
        self.assertEqual(audit(load_compose("examples/reduced-exposure.yaml")), [])

    def test_false_and_unset_user_do_not_imply_root(self):
        self.assertEqual(self.rules({"privileged": False}), set())

    def test_root_variants(self):
        for user in (0, "0:1000", "root", "root:root"):
            with self.subTest(user=user):
                self.assertIn("CL007", self.rules({"user": user}))

    def test_socket_long_form_readonly(self):
        self.assertIn("CL005", self.rules({"volumes": [{"type": "bind", "source": "/run/user/1000/docker.sock", "target": "/socket", "read_only": True}]}))

    def test_named_volume_is_not_host_root(self):
        self.assertNotIn("CL006", self.rules({"volumes": ["data:/"]}))

    def test_anonymous_mount_is_not_host_root(self):
        self.assertNotIn("CL006", self.rules({"volumes": ["/data"]}))

    def test_long_bind_root(self):
        self.assertIn("CL006", self.rules({"volumes": [{"type": "bind", "source": "/", "target": "/host"}]}))

    def test_loopback_v4_v6_and_long_form(self):
        for port in ("127.0.0.1:8080:80", "[::1]:8080:80", {"target": 80, "published": "8080", "host_ip": "127.0.0.1"}):
            with self.subTest(port=port):
                self.assertNotIn("CL008", self.rules({"ports": [port]}))

    def test_published_port_variants(self):
        for port in (80, "8080:80", "0.0.0.0:8080:80", "[::]:8080:80", {"target": 80, "published": 8080}, "${HOST}:8080:80"):
            with self.subTest(port=port):
                self.assertIn("CL008", self.rules({"ports": [port]}))

    def test_expose_is_not_host_publication(self):
        self.assertNotIn("CL008", self.rules({"expose": [80]}))

    def test_windows_mount(self):
        self.assertEqual(volume_parts(r"C:\data:/data"), (r"C:\data", "/data", True))

    def test_capability_prefix(self):
        self.assertIn("CL004", self.rules({"cap_add": ["CAP_SYS_ADMIN"]}))

    def parse(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "compose.yaml"
            path.write_text(text)
            return load_compose(path)

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(InputError):
            self.parse("services:\n  a:\n    privileged: true\n    privileged: false\n")

    def test_merge_keys_supported(self):
        doc = self.parse("x-base: &base\n  privileged: true\nservices:\n  a:\n    <<: *base\n    privileged: false\n")
        self.assertEqual(audit(doc), [])

    def test_invalid_shapes(self):
        for text in ("[]", "services: {}", "services: {a: null}", "services: {a: {ports: wrong}}", 'services: {a: {privileged: "false"}}'):
            with self.subTest(text=text), self.assertRaises(InputError):
                self.parse(text)

    def test_unsafe_yaml_tag_rejected(self):
        with self.assertRaises(InputError):
            self.parse("!!python/object/apply:os.system ['echo forbidden']")

    def test_size_limit(self):
        with self.assertRaises(InputError):
            self.parse("#" * (1024 * 1024 + 1))

    def test_json_and_exit_status(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["examples/review-needed.yaml", "--format", "json"])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(len(report["findings"]), 8)
        self.assertEqual(report["schema_version"], 1)

    def test_none_threshold(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["examples/review-needed.yaml", "--fail-on", "none"]), 0)

    def test_invalid_input_json(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["does-not-exist.yaml", "--format", "json"])
        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(output.getvalue()))

    def test_secret_values_not_in_report(self):
        findings = audit({"services": {"a": {"privileged": True, "environment": {"PASSWORD": "secret-marker"}}}})
        self.assertNotIn("secret-marker", json.dumps([f.to_dict() for f in findings]))


if __name__ == "__main__":
    unittest.main()
