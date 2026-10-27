"""Validate knowledge v3 against the uploaded 1,279-pair source."""
import argparse,collections,hashlib,json
from pathlib import Path

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source',type=Path,default=Path('/mnt/data/high_quality_repair_pairs.json'))
    p.add_argument('--jsonl',type=Path,default=Path(__file__).with_name('knowledge_v3_all.jsonl'))
    args=p.parse_args()
    src=json.loads(args.source.read_text(encoding='utf-8'))['samples']
    records=[json.loads(l) for l in args.jsonl.open(encoding='utf-8') if l.strip()]
    assert len(src)==len(records)==1279
    assert len({x['sample_id'] for x in records})==len(records)
    by_id={x['sample_id']:x for x in records}
    for row in src:
        sid=row['sample_id'];v=by_id[sid]
        assert v['source']['original_descriptions']=={k:row[k] for k in ('unsafe_behavior','security_change','keep_reason')}
        assert v['source']['full_original_code']['code_before']==row['code_before']
        assert v['source']['full_original_code']['code_after']==row['code_after']
        for side in ('before','after'):
            anno=row['review_annotations']['locations'][side]
            out=v['evidence']['reviewed_'+side]
            assert len(out)==len(anno)
            for i,f in enumerate(anno):
                assert f['source_text']==out[i]['code']
        refs={z['evidence_id'] for side in ('before','after') for z in v['evidence']['reviewed_'+side]}
        refs|={z['evidence_id'] for z in v['evidence']['patch_changes']}
        for k in ('dangerous_operation_and_variable_roles',):
            assert set(v[k]['source_evidence_ids']).issubset(refs)
        for guard in v['safety_counterevidence_and_equivalent_protection']['after_guards_observed_in_added_source']:
            assert guard['from_evidence_id'] in refs
    counts=collections.Counter(x['source']['metadata']['dataset'] for x in records)
    print('PASS: 1279 unique IDs, original prose, full code, all review fragments, patch guard IDs; datasets',dict(counts))
if __name__=='__main__':main()
