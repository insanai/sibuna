#!/usr/bin/env python3
"""Run complete admission operations from two external Python client processes over SSH.

The generator's clock includes its IPC and HTTP costs, excludes SSH transport and proof
preparation, and never measures native verifier nanoseconds. Fresh proofs are used once.
"""
from dataclasses import asdict
import json
import shlex
import subprocess

REMOTE = """
import concurrent.futures,http.client,json,multiprocessing,os,sys,time
data=json.load(sys.stdin)
os.sched_setaffinity(0,sorted(os.sched_getaffinity(0))[:2])
def worker(groups):
    counts={};requests=0;minimum=None;maximum=None
    connection=http.client.HTTPConnection(data['host'],data['port'],timeout=15)
    connection.connect()
    try:
        for group in groups:
            jar={}
            for task in group:
                headers=dict(task['headers'])
                if jar: headers['Cookie']='; '.join(k+'='+v for k,v in jar.items())
                connection.request(task['method'],task['path'],task['body'],headers)
                reply=connection.getresponse();body=reply.read()
                if reply.status!=task['expected']: raise ValueError('unexpected admission status')
                requests+=1;key=str(reply.status);counts[key]=counts.get(key,0)+1
                for k,v in reply.getheaders():
                    if k.lower()=='set-cookie':
                        pair=v.split(';',1)[0];name,value=pair.split('=',1);jar[name]=value
                if '/__sibuna/challenge.json' in task['path']:
                    bits=json.loads(body)['difficulty']
                    minimum=bits if minimum is None else min(minimum,bits)
                    maximum=bits if maximum is None else max(maximum,bits)
        return {'statuses':counts,'requests':requests,'issued_bits_min':minimum,
                'issued_bits_max':maximum}
    finally: connection.close()
rows=[]
context=multiprocessing.get_context('fork')
with concurrent.futures.ProcessPoolExecutor(2,mp_context=context) as pool:
    # Launch workers and establish one disposable warm connection before timing.
    list(pool.map(worker,[[],[]]))
    for groups in data['batches']:
        half=len(groups)//2
        if not half or half*2!=len(groups):
            raise ValueError('batch must split into two clients')
        start=time.perf_counter_ns()
        replies=list(pool.map(worker,[groups[:half],groups[half:]]))
        elapsed=time.perf_counter_ns()-start
        statuses={}
        for reply in replies:
            for k,v in reply['statuses'].items():statuses[k]=statuses.get(k,0)+v
        bits=[r['issued_bits_min'] for r in replies if r['issued_bits_min'] is not None]
        maxima=[r['issued_bits_max'] for r in replies if r['issued_bits_max'] is not None]
        rows.append({'operations':len(groups),'requests':sum(r['requests'] for r in replies),
                     'elapsed_ns':elapsed,'operations_per_second':len(groups)*1e9/elapsed,
                     'statuses':statuses,'issued_bits_min':min(bits) if bits else None,
                     'issued_bits_max':max(maxima) if maxima else None})
print(json.dumps(rows))
"""


def measure(generator, port, batches):
    if not generator.remote:
        raise ValueError("admission batches require the separate SSH load host")
    command = [*generator.ssh, generator.remote, "python3 -c " + shlex.quote(REMOTE)]
    payload = {"host": generator.target, "port": port,
               "batches": [[[asdict(task) for task in group] for group in batch]
                           for batch in batches]}
    output = subprocess.check_output(command, input=json.dumps(payload), text=True,
                                     stderr=subprocess.STDOUT)
    rows = json.loads(output)
    for row, batch in zip(rows, batches, strict=True):
        expected = {}
        for group in batch:
            for task in group:
                status = str(task.expected)
                expected[status] = expected.get(status, 0) + 1
        if (row["statuses"] != expected or row["operations"] != len(batch)
                or row["requests"] != sum(len(group) for group in batch)):
            raise ValueError("admission batch status/count validation failed")
    return rows
