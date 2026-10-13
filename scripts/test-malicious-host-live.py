#!/usr/bin/env python3
"""Run the live runner against a fake CLI; no cluster or credentials are used."""

import base64
import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("malicious-host-live.sh")
MOCK = r'''
import json, os, pathlib, sys
a = sys.argv[1:]
while a and (a[0] == '-n' or a[0].startswith('--request-timeout=')):
    a = a[2:] if a[0] == '-n' else a[1:]
case = os.environ['MOCK_CASE']
state = pathlib.Path(os.environ['MOCK_STATE'])
pod = json.loads((state / 'pod.json').read_text())
def error(message):
    print(message, file=sys.stderr)
    sys.exit(1)
if a[0] == 'version':
    if case == 'unreachable': error('connection refused')
elif a[:2] == ['get', 'deployment']:
    print(json.dumps({'spec': {'selector': {'matchLabels': {'app': 'test'}}, 'template': {'metadata': pod['metadata'], 'spec': pod['spec']}}}))
elif a[:2] == ['get', 'pods']:
    print(json.dumps({'items': [pod]}))
elif a[:2] == ['get', 'pod']:
    name = a[2]
    if name != 'original':
        if case == 'status_error': error('transport error')
        pod['metadata']['name'] = name
        pod['status']['conditions'][0]['status'] = 'False'
        pod['status']['containerStatuses'] = [
            {'name': c, 'state': {'waiting': {'message': 'CreateContainerRequest is blocked by policy'}}}
            for c in ['app', 'mhs-extra']
        ]
        if name == 'mhs-initdata' and case == 'kms_ready':
            pod['status']['conditions'][0]['status'] = 'True'
    pod['status']['ephemeralContainerStatuses'] = [{'name': 'mhs-debug', 'state': {'waiting': {'message': 'CreateContainerRequest is blocked by policy'}}}]
    print(json.dumps(pod))
elif a[0] == 'exec':
    if case == 'exec_transport': error('unable to upgrade connection')
    if case == 'missing_shell': error('executable sh not found')
    if case != 'exec_allowed': error('ExecProcessRequest is blocked by policy')
elif a[0] == 'logs':
    if a[1] == 'mhs-initdata':
        if case not in ['kms_timeout', 'kms_transport']: print('attestation_unknown')
        if case == 'kms_transport': error('transport failure with attestation_unknown in an unrelated error')
    elif case == 'logs_error': error('connection refused')
    elif case == 'logs_leak': print('workload log data')
elif a[0] == 'cp':
    if case == 'cp_error': error('tar not found')
    error('ExecProcessRequest is blocked by policy')
elif a[0] == 'attach':
    if case == 'attach_timeout': sys.exit(124)
    error('WriteStreamRequest is blocked by policy')
elif a[0] in ['create', 'debug']:
    if case == 'api_denied': error('Forbidden by RBAC')
elif a[0] not in ['delete', 'annotate']:
    error('unexpected mock command: ' + str(a))
'''


class LiveRunner(unittest.TestCase):
    def run_case(self, case, configured=True):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initdata = b'algorithm = "sha384"\nversion = "0.1.0"\n[data]\n"policy.rego" = \'\'\'\npackage agent_policy\n\'\'\'\n'
            pod = {
                "metadata": {
                    "name": "original", "uid": "unchanged", "labels": {"app": "test"},
                    "annotations": {"io.katacontainers.config.hypervisor.cc_init_data": base64.b64encode(gzip.compress(initdata)).decode()},
                },
                "spec": {
                    "containers": [{"name": "app", "image": "example@sha256:" + "a" * 64, "env": [{"name": "A", "value": "1"}], "volumeMounts": []}],
                    "volumes": [],
                },
                "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}], "containerStatuses": [{"name": "app", "restartCount": 0}]},
            }
            (root / "pod.json").write_text(json.dumps(pod))
            for name, code in [
                ("kubectl", MOCK),
                ("timeout", "import os,sys; os.execvp(sys.argv[2],sys.argv[2:])\n"),
            ]:
                executable = root / name
                executable.write_text(f"#!{sys.executable}\n" + code)
                executable.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       MOCK_CASE=case, MOCK_STATE=str(root), MHS_NAMESPACE="test",
                       MHS_DEPLOYMENT="test", MHS_TIMEOUT="1", MHS_NODE_SHELL="")
            env.pop("KUBECONFIG", None)
            if configured:
                env["KUBECONFIG"] = str(root / "unused-config")
            return subprocess.run(["bash", str(SCRIPT)], env=env, text=True,
                                  capture_output=True, timeout=30)

    def test_explicit_denials_pass_and_optional_checks_are_reported(self):
        result = self.run_case("good")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("required checks passed; 2 optional checks skipped", result.stdout)
        self.assertIn("ephemeral debug container", result.stdout)

    def test_unrelated_errors_and_successful_exec_never_pass(self):
        for case in ["exec_transport", "missing_shell", "exec_allowed", "logs_error",
                     "logs_leak", "cp_error", "attach_timeout", "api_denied", "status_error"]:
            with self.subTest(case=case):
                result = self.run_case(case)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("required checks passed", result.stdout)

    def test_kms_rejection_requires_evidence_and_ready_takes_priority(self):
        for case in ["kms_timeout", "kms_transport", "kms_ready"]:
            with self.subTest(case=case):
                result = self.run_case(case)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("the KMS refused: attestation_unknown", result.stdout)

    def test_configured_cluster_failure_is_an_error_and_no_config_is_a_skip(self):
        result = self.run_case("unreachable")
        self.assertEqual(result.returncode, 2)
        result = self.run_case("good", configured=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn("skipped", result.stdout)


if __name__ == "__main__":
    unittest.main()
