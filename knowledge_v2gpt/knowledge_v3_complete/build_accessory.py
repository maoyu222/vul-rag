from pathlib import Path
import json,hashlib,zipfile
D=Path(__file__).parent
source=D/'knowledge_v3_all.jsonl'
all_path=D/'knowledge_v3_all.json'
retr_path=D/'knowledge_v3_retrieval.jsonl'
with source.open(encoding='utf-8') as fi, all_path.open('w',encoding='utf-8') as fo, retr_path.open('w',encoding='utf-8') as fr:
    fo.write('[\n')
    first=True
    for line in fi:
        d=json.loads(line)
        fo.write(('' if first else ',\n')+line.strip());first=False
        m=d['source']['metadata'];v=d['source']['original_descriptions'];det=d['dangerous_operation_and_variable_roles'];safe=d['safety_counterevidence_and_equivalent_protection'];e=d['evidence']
        item={
            'sample_id':d['sample_id'],
            'metadata':{k:m.get(k) for k in ('dataset','project','function_name','file_path','cwe','vulnerability_type')},
            'mechanism_description':v['unsafe_behavior'],
            'operation_calls':[{'callee':x['callee'],'roles':x['roles']} for x in det['observed_call_sites']],
            'named_symbols':det['source_named_symbols_in_changed_code'],
            'candidate_trigger_clauses':d['vulnerability_trigger_logic']['case_specific_trigger_or_failure_statements'],
            'observed_patch_mechanism':v['security_change'],
            'observed_patch_conditions':[x['predicate'] for x in safe['after_guards_observed_in_added_source']],
            'relevant_before_source':[x['code'] for x in e['reviewed_before']],
            'relevant_after_source':[x['code'] for x in e['reviewed_after']],
            'assumptions_limits_unknowns':v['keep_reason'],
            'semantic_review_status':'not_independently_reviewed',
            'retrieval_text':'\n'.join((m['vulnerability_type'],str(m['cwe']),v['unsafe_behavior'],v['security_change'],v['keep_reason']))
        }
        fr.write(json.dumps(item,ensure_ascii=False,separators=(',',':'))+'\n')
    fo.write('\n]\n')
print('generated',[(x.name,x.stat().st_size) for x in (all_path,retr_path)])
