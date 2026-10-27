"""Read or render one case in the produced knowledge file. Python stdlib only."""
import argparse,json
from pathlib import Path

def fetch(jsonl, sample_id):
    with open(jsonl,encoding='utf-8') as f:
        for line in f:
            record=json.loads(line)
            if record['sample_id']==sample_id:return record
    raise KeyError(sample_id)

def as_detection_context(r):
    p=r['source']['original_descriptions']
    op=r['dangerous_operation_and_variable_roles']
    safe=r['safety_counterevidence_and_equivalent_protection']
    after='\n\n'.join(x['code'] for x in r['evidence']['reviewed_after'])
    before='\n\n'.join(x['code'] for x in r['evidence']['reviewed_before'])
    return '\n'.join([
      '样本 ID: '+r['sample_id'],
      '危险机制（来源原文，不代表目标代码已存在漏洞）: '+p['unsafe_behavior'],
      '危险操作角色: '+json.dumps(op['observed_call_sites'],ensure_ascii=False),
      '源代码修复前关键片段:\n'+before,
      '源代码修复后关键片段:\n'+after,
      '已观察到的修复机制: '+p['security_change'],
      '新增源码条件（只代表补丁事实，不自动证明安全）: '+json.dumps(safe['after_guards_observed_in_added_source'],ensure_ascii=False),
      '前提及未证实事项: '+p['keep_reason'],
      '要求：判断目标函数时，需要重新匹配实际操作、输入约束、类型、容量、控制流和安全反证；否则返回证据不足。'
    ])
if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--file',type=Path,default=Path(__file__).with_name('knowledge_v3_all.jsonl'));a.add_argument('--id',required=True);a.add_argument('--format',choices=['json','prompt'],default='prompt');opt=a.parse_args()
    r=fetch(opt.file,opt.id)
    print(as_detection_context(r) if opt.format=='prompt' else json.dumps(r,ensure_ascii=False,indent=2))
