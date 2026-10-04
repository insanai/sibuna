#!/usr/bin/env python3
"""HTTP load generation locally or over SSH, without exporting product credentials.

SSH carries configuration and results; HTTP requests go directly from the remote generator
to the product. wrk's own clock and histogram exclude SSH setup and result transfer.
"""
import json
import re
import shlex
import subprocess

REMOTE = """
import hashlib,json,os,platform,subprocess,sys,tempfile
from pathlib import Path
data=json.load(sys.stdin)
allowed=sorted(os.sched_getaffinity(0))
cpus=allowed[:2]
if len(cpus)!=2: raise RuntimeError('generator requires two allowed CPUs')
os.sched_setaffinity(0,cpus)
environment=os.environ.copy()
if data.get('library_dir'): environment['LD_LIBRARY_PATH']=data['library_dir']
if data['operation']=='identity':
    result=subprocess.run([data['wrk'],'--version'],env=environment,text=True,
                          stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if result.returncode not in (0,1): raise RuntimeError(result.stdout)
    cpu=next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text()
              .splitlines() if line.startswith('model name')), 'unknown')
    print(json.dumps({'host':platform.node(),'os':platform.platform(),'cpu':cpu,
                      'cpus':cpus,'wrk':result.stdout.strip().splitlines()[0],
                      'wrk_sha256':hashlib.sha256(Path(data['wrk']).read_bytes()).hexdigest()}))
else:
    with tempfile.TemporaryDirectory(prefix='sibuna-http-load-') as name:
        script=Path(name)/'request.lua'
        script.write_text(data['script'])
        command=[data['wrk'],*data['arguments'],'-s',str(script),data['url']]
        subprocess.run(command,env=environment,check=True)
"""


class HttpLoad:
    def __init__(self, target="127.0.0.1", remote=None, wrk="wrk", library_dir=None,
                 known_hosts=None):
        self.target, self.remote = target, remote
        self.wrk, self.library_dir = wrk, library_dir
        self.ssh = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]
        if known_hosts:
            self.ssh += ["-o", f"UserKnownHostsFile={known_hosts}"]

    def remote_call(self, operation, **values):
        command = [*self.ssh, self.remote, "python3 -c " + shlex.quote(REMOTE)]
        payload = {"operation": operation, "wrk": self.wrk,
                   "library_dir": self.library_dir, **values}
        return subprocess.check_output(command, input=json.dumps(payload), text=True,
                                       stderr=subprocess.STDOUT)

    def identity(self):
        return json.loads(self.remote_call("identity")) if self.remote else None

    def run(self, port, path, headers, load, script):
        arguments = [f"-t{load['threads']}", f"-c{load['connections']}",
                     f"-d{load['seconds']}s"]
        for key, value in headers.items():
            arguments += ["-H", f"{key}: {value}"]
        url = f"http://{self.target}:{port}{path}"
        if self.remote:
            output = self.remote_call("run", arguments=arguments, script=script.read_text(),
                                      url=url)
        else:
            output = subprocess.check_output([self.wrk, *arguments, "-s", str(script), url],
                                             text=True, stderr=subprocess.STDOUT)
        match = re.search(r"WRKJSON (\{.*\})", output)
        if not match:
            raise RuntimeError(output)
        return json.loads(match.group(1))
