#!/usr/bin/env python3
"""Validate chart constraints and optionally deploy the actual image in kind."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.request

CHART = Path(__file__).resolve().parents[1] / 'distribution/helm/sibuna'
NODE = 'kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0'


def validate():
    import yaml
    command = ['helm', 'template', 'check', str(CHART)]
    for options in [[], ['--set', 'secret.existingSecret=seed,upstream.host=origin.default.svc'],
                    ['--set', 'secret.existingSecret=seed,service.port=70000'],
                    ['--set', 'secret.existingSecret=seed,replicaCount=2']]:
        result = subprocess.run(command + options, capture_output=True)
        assert result.returncode != 0, f'unsafe chart settings accepted: {options}'
    for options in [[], ['--set', 'persistence.existingClaim=operator-state'], ['--set', 'persistence.enabled=false']]:
        output = subprocess.check_output(command + ['--set', 'secret.existingSecret=seed'] + options)
        documents = {d['kind']: d for d in yaml.safe_load_all(output) if d}
        deployment = documents['Deployment']['spec']
        assert deployment['replicas'] == 1 and deployment['strategy']['type'] == 'Recreate'
        pod = deployment['template']['spec']
        assert pod['automountServiceAccountToken'] is False
        assert pod['securityContext']['fsGroup'] == 65532
        container = pod['containers'][0]
        assert container['securityContext']['readOnlyRootFilesystem'] is True
        assert '--console' not in container['args']
        assert container['args'][container['args'].index('--data-dir') + 1] == '/var/lib/sibuna/data'
        assert pod['volumes'][0]['secret']['defaultMode'] == 0o440
        assert documents['Service']['spec']['type'] == 'ClusterIP'
        assert documents['NetworkPolicy']['spec']['ingress'] == []
        assert documents['NetworkPolicy']['spec']['egress'] == []
        assert 'Secret' not in documents
        assert ('PersistentVolumeClaim' in documents) == (not options)
    subprocess.run(['helm', 'lint', str(CHART), '--strict', '--set', 'secret.existingSecret=seed'], check=True)


def deploy(image, user_namespace=False):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        env = {**os.environ, 'KUBECONFIG': str(root / 'kubeconfig')}
        def run(*args, capture=False):
            return subprocess.run(args, env=env, check=True, text=True,
                                  stdout=subprocess.PIPE if capture else None).stdout
        name = 'sibuna-qualification-' + str(os.getpid())
        try:
            create_options = []
            if user_namespace:
                # Test-host workaround only, not a setting in the shipped chart.
                config = root / 'kind.yaml'
                config.write_text('apiVersion: kind.x-k8s.io/v1alpha4\nkind: Cluster\nnodes:\n- role: control-plane\n  kubeadmConfigPatches:\n  - |\n    kind: KubeletConfiguration\n    featureGates:\n      KubeletInUserNamespace: true\n')
                create_options = ['--config', str(config)]
            run('kind', 'create', 'cluster', '--name', name, '--image', NODE, '--kubeconfig', env['KUBECONFIG'], '--wait', '120s', *create_options)
            run('kind', 'load', 'docker-image', image, '--name', name)
            run('kubectl', 'create', 'namespace', 'sibuna-test')
            run('kubectl', 'label', 'namespace', 'sibuna-test', 'pod-security.kubernetes.io/enforce=restricted', 'pod-security.kubernetes.io/enforce-version=v1.35')
            seed = root / 'admission.seed'
            seed.write_bytes(secrets.token_bytes(32)); seed.chmod(0o600)
            run('kubectl', '-n', 'sibuna-test', 'create', 'secret', 'generic', 'seed', '--from-file=admission.seed=' + str(seed))
            repository, tag = image.rsplit(':', 1)
            options = ['--namespace', 'sibuna-test', '--set', f'secret.existingSecret=seed,image.repository={repository},image.tag={tag},image.pullPolicy=Never,networkPolicy.enabled=false']
            # kind's default CNI is not a NetworkPolicy enforcement test.
            run('helm', 'install', 'check', str(CHART), *options, '--wait', '--timeout', '180s')
            claim = json.loads(run('kubectl', '-n', 'sibuna-test', 'get', 'pvc', 'check-sibuna', '-o', 'json', capture=True))
            before = claim['metadata']['uid']
            forwarding = subprocess.Popen(['kubectl', '-n', 'sibuna-test', 'port-forward', 'service/check-sibuna', '18080:8080'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(30):
                    try:
                        with urllib.request.urlopen('http://127.0.0.1:18080/__sibuna/health', timeout=1) as response:
                            assert response.status == 200
                        break
                    except OSError:
                        time.sleep(1)
                else:
                    raise AssertionError('chart listener did not become healthy')
            finally:
                forwarding.terminate(); forwarding.wait(timeout=10)
            run('helm', 'upgrade', 'check', str(CHART), *options, '--set', 'podAnnotations.qualification=restart', '--wait', '--timeout', '180s')
            after = json.loads(run('kubectl', '-n', 'sibuna-test', 'get', 'pvc', 'check-sibuna', '-o', 'json', capture=True))
            assert after['metadata']['uid'] == before
            run('helm', 'uninstall', 'check', '--namespace', 'sibuna-test', '--wait')
            run('kubectl', '-n', 'sibuna-test', 'get', 'pvc', 'check-sibuna')
            run('kubectl', '-n', 'sibuna-test', 'get', 'secret', 'seed')
        except Exception:
            # Diagnostic resources/events expose no Secret values.
            subprocess.run(['kubectl', '-n', 'sibuna-test', 'get', 'pods,pvc'], env=env)
            subprocess.run(['kubectl', '-n', 'sibuna-test', 'get', 'events', '--sort-by=.lastTimestamp'], env=env)
            subprocess.run(['kubectl', '-n', 'sibuna-test', 'logs', 'deployment/check-sibuna', '--tail=80'], env=env)
            subprocess.run(['kubectl', '-n', 'sibuna-test', 'get', 'pods', '-o',
                            'jsonpath={range .items[*]}{.status.containerStatuses}{"\\n"}{end}'], env=env)
            raise
        finally:
            run('kind', 'delete', 'cluster', '--name', name)
    print('actual chart install, health, Recreate upgrade and retained PVC/Secret passed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image')
    parser.add_argument('--user-namespace', action='store_true', help='test-only kubelet workaround for nested Incus/user-namespace hosts')
    args = parser.parse_args()
    validate()
    if args.image:
        deploy(args.image, args.user_namespace)
