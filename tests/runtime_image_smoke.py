"""Exercise the actual packaged service in an isolated, networkless container."""

import csv
import hashlib
import json
from pathlib import Path
import threading
import types

import flow_predictor_cnsm as runtime


def main():
    assert runtime.DRY_RUN and not runtime.AUTO_MITIGATE
    assert runtime._etcd is None
    assert runtime.engine.agentic is None and runtime.engine.collaboration is None
    assert not runtime.collector.thread.is_alive()
    fixed_ns = 1_700_000_000_000_000_000
    runtime.now_ns = lambda: fixed_ns
    runtime.engine.started_ns = fixed_ns
    identifiers = iter(range(1, 100))
    runtime.uuid.uuid4 = lambda: types.SimpleNamespace(hex=f'{next(identifiers):012x}' + '0' * 20)
    client = runtime.app.test_client()

    model = client.get('/predictor/model')
    assert model.status_code == 200 and model.json['loaded']
    assert model.json['mode'] == 'offline'

    key = 'flow:1:10.0.0.1->10.0.0.8'
    meta = dict(type='flow', dpid=1, nw_src='10.0.0.1', nw_dst='10.0.0.8')
    for step, counter in enumerate([0, 125000, 250000, 375000, 12875000, 25375000,
                                    25500000, 25500000, 25500000, 25625000]):
        runtime.engine.ingest(key, meta, counter, 1_700_000_000.0 + step)
    assert runtime.engine.anomalies
    assert all(not row.get('mitigation', {}).get('executed') for row in runtime.engine.anomalies)

    # Existing series must consult the live floor after config updates.
    other_key = 'flow:2:10.0.0.2->10.0.0.7'
    other_meta = dict(type='flow', dpid=2, nw_src='10.0.0.2', nw_dst='10.0.0.7')
    runtime.engine.ingest(other_key, other_meta, 0, 1_700_000_000.0)
    assert client.post('/predictor/config', json={'min_rate_bps': 2_000_000}).status_code == 200
    runtime.engine.ingest(other_key, other_meta, 125000, 1_700_000_001.0)
    assert runtime.engine.series[other_key].predictor.n == 0
    assert client.post('/predictor/config', json={'min_rate_bps': 1}).status_code == 200
    runtime.engine.ingest(other_key, other_meta, 250000, 1_700_000_002.0)
    assert runtime.engine.series[other_key].predictor.n == 1

    endpoints = {}
    for route in ['model', 'status', 'predictions', 'anomalies', 'export/status', 'agent']:
        response = client.get('/predictor/' + route)
        assert response.status_code == 200, (route, response.status_code)
        endpoints[route] = response.json

    runtime._exporter.close()
    csv_files = {}
    for path in sorted(Path(runtime.EXPORT_DIR).glob('*.csv')):
        with path.open() as handle:
            rows = list(csv.DictReader(handle))
        assert rows
        csv_files[path.name] = dict(rows=len(rows), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    assert len(csv_files) == 2
    assert not runtime.collector.thread.is_alive()
    assert len(threading.enumerate()) == 1
    payload = dict(endpoints=endpoints, csv_files=csv_files,
                   counters=dict(series=len(runtime.engine.series),
                                 anomalies=len(runtime.engine.anomalies),
                                 suppressed=runtime.engine.anomalies_suppressed))
    encoded = json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    print(json.dumps(dict(status='PASSED', network='none', payload_sha256=hashlib.sha256(encoded).hexdigest(),
                          result=payload), sort_keys=True))


if __name__ == '__main__':
    main()
