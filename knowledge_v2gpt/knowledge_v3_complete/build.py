#!/usr/bin/env python3
"""Lossless, source-grounded per-pair C/C++ vulnerability mechanism extractor.
Does NOT claim to use an LLM, AST parser or prove guards/capacity.
"""
import argparse, csv, difflib, hashlib, json, re, zipfile
from pathlib import Path
from collections import Counter,defaultdict

SEMANTIC_VERSION='3.0-source-grounded'
CALL_ARGS={
 'memcpy':['destination','source','byte_count'], 'memmove':['destination','source','byte_count'], 'memset':['destination','value','byte_count'],
 'strcpy':['destination','source'], 'strncpy':['destination','source','maximum_count'], 'strcat':['destination','source'],
 'strncat':['destination','source','maximum_count'], 'sprintf':['destination','format_string'], 'snprintf':['destination','capacity_argument','format_string'],
 'vsprintf':['destination','format_string','argument_list'], 'vsnprintf':['destination','capacity_argument','format_string','argument_list'],
 'gets':['destination'], 'fgets':['destination','maximum_count','stream'],
 'read':['file_descriptor','destination','byte_count'], 'recv':['socket','destination','byte_count'],
 'fread':['destination','element_size','element_count','stream'], 'strncpy_s':['destination','destination_capacity','source','maximum_count'],
 'malloc':['allocation_size'], 'calloc':['element_count','element_size'], 'realloc':['old_pointer','allocation_size'],
 'free':['released_pointer'], 'delete':['released_pointer'], 'strlen':['input_string'], 'memcmp':['first_buffer','second_buffer','byte_count'],
 'strcmp':['first_string','second_string'], 'strncpy':['destination','source','maximum_count'],
 'open':['path','flags','permissions'], 'fopen':['path','mode'], 'unlink':['path'], 'memchr':['buffer','character','byte_count'],
 'X509_check_host':['certificate','hostname','hostname_length','flags','peername'],
 'SSL_get_verify_result':['connection'],
}
SKIP_CALLS=set('if while for switch sizeof alignof return throw catch static_cast reinterpret_cast dynamic_cast const_cast typeof defined do'.split())
CALL_REGEX=re.compile(r'(?<![\w])([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)?)\s*\(')
COND_REGEX=re.compile(r'\b(if|else\s+if|while|for)\s*\(')
RISK_RE=re.compile(r'\b(if|when|unless|where|overflows?|underflows?|out.of.bounds|beyond|exceed|dereference|freed|leak|invalid|without|fails?|can|could|may|would|allows?|bypass|unbounded|wraps?|undefined|attack|unsafe)\b',re.I)
PREREQ_RE=re.compile(r'\b(when|if|requires?|assum(?:e|es|ing)|provided|only (if|when)|under (the|a)|in the .*?branch|comes? from|supplied by|derived from|input|before)\b',re.I)
LIMIT_RE=re.compile(r'\b(assum|unknown|undefined|not (given|provided|shown|established|verified|prove|known|confirm|cover|assert|infer)|cannot|does not|outside|depends on|requires|only|limited|unresolved|remain|without|may|could|conditional)\b',re.I)
KEYWORDS_RISK=set('memcpy memmove malloc realloc free new delete sprintf snprintf strcpy strcat read recv fwrite fread dereference buffer array offset size length pointer memcpy_s fopen open unlink shift divide division index memcpy'.split())


def normalize(x): return re.sub(r'\s+', '', x or '')
def sentences(s):
    # Keep original sentence spans verbatim; no automatic restating of an unverified claim.
    s=(s or '').strip()
    chunks=re.split(r'(?<=[.!?])\s+(?=[A-Za-z(])|(?<=;)\s+(?=[A-Za-z])',s)
    return [t.strip() for t in chunks if t.strip()]

def unique(seq, limit=0):
    seen=set();out=[]
    for x in seq:
        if x not in seen:
            seen.add(x);out.append(x)
            if limit and len(out)>=limit: break
    return out

def find_span(src,fragment, start_line=None):
    if not fragment: return {'status':'empty','start_line':None,'end_line':None}
    start=src.find(fragment)
    if start>=0:
        return {'status':'exact','start_line':src.count('\n',0,start)+1,'end_line':src.count('\n',0,start+len(fragment)-1)+1}
    # Use bounded linear-time whitespace-free lookup below; avoid catastrophic regex matching.
    # Verify line range separately if possible
    src_lines=src.splitlines(); start_idx=(start_line or 0)-1
    if 0 <= start_idx < len(src_lines):
        region='\n'.join(src_lines[start_idx:start_idx+len(fragment.splitlines())])
        if normalize(region)==normalize(fragment):
            return {'status':'whitespace_equivalent','start_line':start_idx+1,'end_line':start_idx+len(fragment.splitlines())}
    # whitespace-free match with an index map: preserves original locations
    chars=[]; idx=[]
    for i,c in enumerate(src):
        if not c.isspace(): chars.append(c);idx.append(i)
    plain=''.join(chars); needle=normalize(fragment); pos=plain.find(needle)
    if pos>=0:
        start=idx[pos];end=idx[pos+len(needle)-1]
        return {'status':'whitespace_equivalent','start_line':src.count('\n',0,start)+1,'end_line':src.count('\n',0,end)+1}
    return {'status':'not_found','start_line':None,'end_line':None}

def balanced(s,p):
    # p points at opening '('
    depth=0; quote=None;escaped=False
    for i in range(p,len(s)):
        c=s[i]
        if quote:
            if escaped: escaped=False
            elif c=='\\': escaped=True
            elif c==quote: quote=None
            continue
        if c in "'\"": quote=c;continue
        if c=='(':depth+=1
        if c==')':
            depth-=1
            if depth==0:return s[p+1:i], i+1
    return None,None

def comma_args(t):
    a=[];q=None;escaped=False;level=0;begin=0
    for i,c in enumerate(t):
        if q:
            if escaped:escaped=False
            elif c=='\\':escaped=True
            elif c==q:q=None
            continue
        if c in "'\"":q=c;continue
        if c in '([{':level+=1
        if c in ')]}':level=max(0,level-1)
        if c==',' and level==0:
            a.append(t[begin:i].strip());begin=i+1
    a.append(t[begin:].strip());return a

def _mask_comments(code):
    # Keep strings (e.g. mode argument "r") but erase actual comments without moving character positions.
    pattern=r'\"(?:\\.|[^\"\\])*\"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/'
    def mask(m):
        t=m.group(0)
        if t.startswith('//') or t.startswith('/*'):
            return ''.join('\n' if c=='\n' else ' ' for c in t)
        return t
    return re.sub(pattern,mask,code)

def get_calls(code, allowed_source_text=None, max_calls=16):
    calls=[]; seen=set()
    if not code:return calls
    masked=_mask_comments(code)
    for m in CALL_REGEX.finditer(masked):
        fn=m.group(1)
        if fn in SKIP_CALLS:continue
        arg_text,end=balanced(code,code.find('(',m.start()))
        if arg_text is None:continue
        base=fn.split('->')[-1].split('.')[-1]
        if base not in CALL_ARGS and allowed_source_text and not re.search(r'\b'+re.escape(base)+r'\b',allowed_source_text,re.I):continue
        if base not in CALL_ARGS and base not in KEYWORDS_RISK:continue
        args=comma_args(arg_text)
        role_names=CALL_ARGS.get(base,[])
        roles=[{'role':r,'expression':args[i],'basis':'argument_position','verified_type_or_capacity':False} for i,r in enumerate(role_names) if i<len(args)]
        signature=code[m.start():min(end,m.start()+450)].strip()
        if signature in seen:continue
        seen.add(signature)
        calls.append({'callee':fn,'invocation':signature,'arguments':args[:10],'roles':roles})
        if len(calls)>=max_calls:break
    return calls

def get_conditions(code, max_conditions=24):
    cond=[];seen=set()
    masked=_mask_comments(code)
    for m in COND_REGEX.finditer(masked):
        start=code.find('(',m.start()); expr,end=balanced(code,start)
        if expr is None:continue
        expr=expr.strip()
        if len(expr)>600 or (m.group(1)=='for' and ';' in expr):continue
        key=(m.group(1),expr)
        if key in seen:continue
        seen.add(key)
        following=code[end:end+220]
        action='not_inferred'
        # Observe simple following statement, not full control flow or dominance
        if re.match(r'\s*\{?\s*(return|goto|break|continue|throw)\b',following):action=re.match(r'\s*\{?\s*(return|goto|break|continue|throw)\b',following).group(1)
        cond.append({'kind':m.group(1).strip(),'predicate':expr,'immediate_action_observed':action,'control_flow_dominance_proven':False})
        if len(cond)>=max_conditions:break
    return cond

def diff_hunks(before,after):
    a=before.splitlines();b=after.splitlines()
    matcher=difflib.SequenceMatcher(None,a,b,autojunk=False)
    changes=[]
    for tag,a0,a1,b0,b1 in matcher.get_opcodes():
        if tag=='equal':continue
        changes.append({'kind':tag,'before_lines':[a0+1,a1] if a1>a0 else None,'after_lines':[b0+1,b1] if b1>b0 else None,'before_code':'\n'.join(a[a0:a1]),'after_code':'\n'.join(b[b0:b1])})
    return changes

def code_tokens(code):
    return set(re.findall(r'\b[A-Za-z_]\w*\b',code))

def evidence(row, changes):
    ann=row['review_annotations'];out={};problems=[]
    for side in ('before','after'):
        src=row['code_'+side];ev=[]
        for i,f in enumerate(ann['locations'][side]):
            t=f.get('source_text',''); loc=find_span(src,t,f.get('start_line'))
            stat=loc['status']
            if stat=='not_found':problems.append({'side':side,'fragment_index':i,'type':'source_text_not_found'})
            elif stat!='exact':problems.append({'side':side,'fragment_index':i,'type':stat})
            reported=[f.get('start_line'),f.get('end_line')]
            if loc['start_line'] and (loc['start_line']!=reported[0] or loc['end_line']!=reported[1]):
                problems.append({'side':side,'fragment_index':i,'type':'reported_line_range_disagrees','reported':reported,'found':[loc['start_line'],loc['end_line']]})
            ev.append({'evidence_id':f'{side[0].upper()}{i+1:03}','role':'reviewed_source_fragment','source_field':f'review_annotations.locations.{side}[{i}]','reported_location':{'start_line':f.get('start_line'),'end_line':f.get('end_line'),'start_column':f.get('start_column'),'end_column':f.get('end_column')},'actual_location':loc,'code':t})
        out[side]=ev
    patches=[]
    for i,c in enumerate(changes):
        evidence_ids=[]
        for side in ('before','after'):
            code=c[side+'_code']
            if code:
                key=('B' if side=='before' else 'A')+'D'+str(i+1).zfill(3)
                evidence_ids.append(key)
                start,end=c[side+'_lines']
                patches.append({'evidence_id':key,'role':'changed_'+side,'source_field':'computed_line_diff','actual_location':{'status':'exact_computed','start_line':start,'end_line':end},'code':code})
        c['evidence_ids']=evidence_ids
    return out,patches,problems

def extract_text_facts(text, category, ref, limit=12):
    result=[]
    for i,s in enumerate(sentences(text)):
        if 'Current review mechanism description:' in s or 'Repair mechanism description under current review:' in s:
            # Maintain full original text separately and don't create duplicate conclusions
            continue
        if category=='trigger' and not RISK_RE.search(s):continue
        if category=='precondition' and not PREREQ_RE.search(s):continue
        if category=='boundary' and not LIMIT_RE.search(s):continue
        result.append({'statement':s,'provenance_field':ref,'source_span_index':i,'assertion_status':'reported_in_source;not_independently_proven'})
        if len(result)>=limit:break
    if not result and category in ('trigger','precondition'):
        # A required field must never be fabricated; retain the nearest case-specific source
        # sentence as an unparsed claim rather than inventing a symbolic predicate.
        options=[(i,t) for i,t in enumerate(sentences(text)) if 'Current review mechanism description:' not in t]
        if options:
            i,t=max(options, key=lambda item:(sum(bool(re.search(r'\b'+re.escape(term)+r'\b',item[1],re.I)) for term in ('zero','length','size','capacity','pointer','index','input','state','value','overflow','null','failure','error')),len(item[1]))) if category=='trigger' else options[0]
            result=[{'statement':t,'provenance_field':ref,'source_span_index':i,'assertion_status':'source_reported_unparsed_context;not_independently_proven'}]
    return result

def code_operation_candidates(row,changes):
    old_anchor=row['review_annotations']['unsafe_line']
    source=row['unsafe_behavior']
    calls=get_calls(old_anchor,source,14)
    if not calls:
        calls=get_calls('\n'.join(c['before_code'] for c in changes), source,14)
    if not calls:
        calls=get_calls(row['code_before'],source,10)
    # Isolate symbols explicitly shared between mechanism prose and edited source.
    mentioned=code_tokens(source)
    in_patch=code_tokens(old_anchor+'\n'+ '\n'.join(c['before_code']+'\n'+c['after_code'] for c in changes))
    stop=set('the if while and or not else int char return null NULL TRUE FALSE void true false size const static guint gint unsigned signed can after before it that code this value with is of a to from for'.split())
    symbols=[t for t in mentioned & in_patch if len(t)>=2 and t not in stop]
    # prioritise symbols seen in review anchor and longest names
    anchor_tokens=code_tokens(old_anchor)
    symbols.sort(key=lambda s:(s not in anchor_tokens, -len(s),s))
    return calls,symbols[:42]

def guard_candidates(changes):
    entries=[]
    for j,c in enumerate(changes):
        added=c['after_code']
        if not added:continue
        for i,cond in enumerate(get_conditions(added,14)):
            entries.append({'constraint_id':f'G{j+1:03}_{i+1:02}','predicate':cond['predicate'],'statement_kind':cond['kind'],'immediate_action_observed':cond['immediate_action_observed'],'from_evidence_id':'AD'+str(j+1).zfill(3),'evidence_status':'observed_in_changed_after_source','guard_reaches_dangerous_operation':'not_proven','equivalent_guard_for_other_code':'not_proven'})
    return entries[:80]

def before_condition_candidates(changes):
    out=[]
    for j,c in enumerate(changes):
        for i,cond in enumerate(get_conditions(c['before_code'],8)):
            out.append({'predicate':cond['predicate'],'from_evidence_id':'BD'+str(j+1).zfill(3)})
    return out[:40]

def model(row):
    b=row['code_before'];a=row['code_after'];changes=diff_hunks(b,a)
    ev,patch_ev,problems=evidence(row,changes)
    calls,symbols=code_operation_candidates(row,changes)
    guards=guard_candidates(changes)
    orig=before_condition_candidates(changes)
    unsafe=row['unsafe_behavior'];fix=row['security_change'];keep=row['keep_reason']
    sid=row['sample_id'];meta={k:row.get(k) for k in ('sample_id','dataset','project','cve','cwe','fix_commit','parent_commit','file_path','function_name','vulnerability_type')}
    diff_reported=row['function_diff']
    if not changes:problems.append({'type':'no_code_change'})
    if any('not_found' in x.get('type','') for x in problems):problems.append({'type':'evidence_location_review_required'})
    # Qualifiers are source assertions, never upgraded to proven safety guarantees.
    limitation=extract_text_facts(keep,'boundary','keep_reason',12)
    unknowns=unique([x['statement'] for x in limitation],14)
    if not unknowns:unknowns=[keep]
    flags=[]
    if not row.get('cve'):flags.append('missing_cve')
    if not row.get('parent_commit'):flags.append('missing_parent_commit')
    if problems:flags.append('review_source_alignment')
    if not guards:flags.append('no_explicit_changed_if_guard_extracted')
    source={'metadata':meta,'pair_provenance':row.get('pair_provenance',{}),'original_descriptions':{'unsafe_behavior':unsafe,'security_change':fix,'keep_reason':keep},'original_annotation_lines':{'unsafe_line':row['review_annotations'].get('unsafe_line'),'fix_line':row['review_annotations'].get('fix_line'),'repair_pattern':row['review_annotations']['repair_pattern']},'source_content_sha256':{'code_before':hashlib.sha256(b.encode()).hexdigest(),'code_after':hashlib.sha256(a.encode()).hexdigest()},'source_file':'high_quality_repair_pairs.json','full_original_code':{'code_before':b,'code_after':a}}
    out={
     'schema_version':SEMANTIC_VERSION,
     'sample_id':sid,
     'source':source,
     'dangerous_operation_and_variable_roles':{
       'case_specific_mechanism':unsafe,
       'source_evidence_ids':[x['evidence_id'] for x in ev['before']],
       'observed_call_sites':calls,
       'source_named_symbols_in_changed_code':symbols,
       'reviewed_unsafe_code':row['review_annotations'].get('unsafe_line'),
       'role_inference_limits':'Argument positions identify syntactic roles only; aliasing, actual bounds, signedness and types remain unverified unless explicitly shown.'
     },
     'applicability_and_origin':{
       'specific_preconditions_from_case':extract_text_facts(unsafe,'precondition','unsafe_behavior',15),
       'qualified_assumptions_from_boundary':extract_text_facts(keep,'precondition','keep_reason',12),
       'observed_original_branch_conditions':orig,
       'requirements_to_match_in_target':'The same variable relationships, object and operation semantics, reachable path, and type/capacity contracts must be established; similarity by API/CWE alone is insufficient.',
       'facts_not_grounded_by_source':unknowns
     },
     'vulnerability_trigger_logic':{
       'precise_mechanism_reported_by_source':unsafe,
       'case_specific_trigger_or_failure_statements':extract_text_facts(unsafe,'trigger','unsafe_behavior',15),
       'original_changed_conditions':orig,
       'relations_need_proof':['input/state satisfies source-specific preconditions','observed path reaches hazardous operation','all relevant preexisting guards fail to exclude trigger'],
       'exploitability_or_whole_program_reachability':'not_independently_verified'
     },
     'safety_counterevidence_and_equivalent_protection':{
       'actual_patch_mechanism':fix,
       'after_guards_observed_in_added_source':guards,
       'patch_transformations':[{'change_id':'D'+str(i+1).zfill(3),'kind':c['kind'],'before_evidence_id':('BD'+str(i+1).zfill(3)) if c['before_code'] else None,'after_evidence_id':('AD'+str(i+1).zfill(3)) if c['after_code'] else None,'before_code':c['before_code'],'after_code':c['after_code']} for i,c in enumerate(changes)],
       'constraints_and_limits_from_source':keep,
       'equivalent_protection':{'status':'candidate_unverified','proof_basis':fix,'required_checks':'Match the case-specific invariant, operation, actual object capacity/state, correct order and all relevant paths; unlike the patch, no candidate implementation is verified.'},
       'entire_after_function_secure':'not_established'
     },
     'evidence_requirements_and_analysis_methods':{
       'code_before_evidence':[x['evidence_id'] for x in ev['before']],
       'code_after_evidence':[x['evidence_id'] for x in ev['after']],
       'required_target_facts':[{'fact_id':'F1','check_kind':'operation_and_roles','specific_calls':[v['invocation'] for v in calls[:5]],'named_variables':symbols[:20], 'supporting_source_claim':unsafe,'analysis':['identify target roles','trace definitions and uses'],'verification_status':'not_checked'},
         {'fact_id':'F2','check_kind':'trigger_and_reachability','specific_original_conditions':[v['predicate'] for v in orig[:8]],'source_trigger_clauses':[f['statement'] for f in extract_text_facts(unsafe,'trigger','unsafe_behavior',7)],'analysis':['trace branch reachability','check named value/bounds/ownership constraints'],'verification_status':'not_checked'},
         {'fact_id':'F3','check_kind':'counterexample_and_guard_effect','specific_patch_guards':[v['predicate'] for v in guards[:12]],'observed_patch_description':fix,'analysis':['compare conditions and protected operation','validate guard ordering and path coverage'],'verification_status':'not_checked'},
         {'fact_id':'F4','check_kind':'assumptions_and_unknowns','specific_source_limitations':unknowns[:8],'analysis':['check external types/macros/contracts only where relevant'],'verification_status':'not_checked'}],
       'missing_facts_handling':'insufficient_evidence; do not infer safety or vulnerability solely from labels or patch presence'
     },
     'applicability_boundary_and_unknowns':{'original_boundary':keep,'explicit_source_limitations':limitation,'unknown_or_conditional_facts':unknowns,'scope':'local source-pair relationship, not proof of global vulnerability or safety'},
     'evidence':{'reviewed_before':ev['before'],'reviewed_after':ev['after'],'patch_changes':patch_ev,'function_diff_original':diff_reported,'source_alignment_findings':problems},
     'audit':{'extraction_method':'source-specific narrative clause mapping + function line diff + syntactic call/condition parsing; no LLM per sample','semantic_review_status':'not_independently_reviewed','metadata_flags':flags,'source_evidence_syntactically_checkable':not any(x.get('type') in ('source_text_not_found','evidence_location_review_required') for x in problems),'guard_domination_verified':False,'target_implementation_verified':False}
    }
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--input',type=Path,default=Path('/mnt/data/high_quality_repair_pairs.json'));ap.add_argument('--output',type=Path,default=Path('/mnt/data/knowledge_v3_complete'));args=ap.parse_args()
    root=args.output;root.mkdir(parents=True,exist_ok=True)
    raw=args.input.read_bytes();data=json.loads(raw)
    assert len(data['samples'])==1279
    all_records=[]; by=defaultdict(list);bad=[];counts=Counter()
    for row in data['samples']:
        o=model(row);all_records.append(o);by[row['dataset']].append(o)
        if o['evidence']['source_alignment_findings']:bad.append({'sample_id':o['sample_id'],'findings':o['evidence']['source_alignment_findings']})
        counts.update([o['source']['metadata']['vulnerability_type']])
    ids=[x['sample_id'] for x in all_records]
    assert len(ids)==len(set(ids))==1279
    assert all(len(x['evidence']['reviewed_before'])==len(src['review_annotations']['locations']['before']) and len(x['evidence']['reviewed_after'])==len(src['review_annotations']['locations']['after']) for x,src in zip(all_records,data['samples']))
    # Original narratives must be 100% intact, across every dataset.
    assert all(x['source']['original_descriptions']['unsafe_behavior']==row['unsafe_behavior'] and x['source']['original_descriptions']['security_change']==row['security_change'] and x['source']['original_descriptions']['keep_reason']==row['keep_reason'] for x,row in zip(all_records,data['samples']))
    for dataset, arr in by.items():
        name=dataset.lower(); (root/f'knowledge_v3_{name}.json').write_text(json.dumps({'schema_version':SEMANTIC_VERSION,'dataset':dataset,'knowledge':arr},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (root/'knowledge_v3_all.jsonl').write_text(''.join(json.dumps(v,ensure_ascii=False,separators=(',',':'))+'\n' for v in all_records),encoding='utf-8')
    manifest=[]
    for i,x in enumerate(all_records):
        m=x['source']['metadata'];a=x['audit'];e=x['evidence']
        manifest.append({'sample_id':x['sample_id'],'dataset':m['dataset'],'project':m['project'],'function_name':m['function_name'],'cwe':';'.join(m['cwe'] or []),'vulnerability_type':m['vulnerability_type'],'repair_pattern':x['source']['original_annotation_lines']['repair_pattern'],'before_fragments':len(e['reviewed_before']),'after_fragments':len(e['reviewed_after']),'changes':len(x['safety_counterevidence_and_equivalent_protection']['patch_transformations']),'guard_candidates':len(x['safety_counterevidence_and_equivalent_protection']['after_guards_observed_in_added_source']),'source_alignment_issues':len(e['source_alignment_findings']),'semantic_review_status':a['semantic_review_status']})
    with (root/'knowledge_v3_index.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=manifest[0].keys());w.writeheader();w.writerows(manifest)
    (root/'alignment_findings.json').write_text(json.dumps(bad,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    # human-inspectable exemplars from diverse vulnerability types and repair classes
    sample_ids=['megavul_248517','cleanvul_s4_003483','cleanvul_s4_001219','megavul_291580','megavul_339805','megavul_176114','megavul_295294']
    examples=[x for x in all_records if x['sample_id'] in sample_ids]
    (root/'critical_case_examples.json').write_text(json.dumps(examples,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    status=Counter(x['audit']['semantic_review_status'] for x in all_records)
    issues=Counter(q['type'] for x in all_records for q in x['evidence']['source_alignment_findings'])
    info={'schema_version':SEMANTIC_VERSION,'total':len(all_records),'unique_ids':len(set(ids)),'datasets':{k:len(v) for k,v in by.items()},'vulnerability_type_distribution':dict(counts),'source_sha256':hashlib.sha256(raw).hexdigest(),'total_reviewed_before_fragments':sum(len(x['evidence']['reviewed_before']) for x in all_records),'total_reviewed_after_fragments':sum(len(x['evidence']['reviewed_after']) for x in all_records),'total_changed_code_segments':sum(len(x['evidence']['patch_changes']) for x in all_records),'records_with_alignment_notes':len(bad),'alignment_issue_distribution':dict(issues),'records_with_code_guard_candidates':sum(bool(x['safety_counterevidence_and_equivalent_protection']['after_guards_observed_in_added_source']) for x in all_records),'semantic_review_status':dict(status),'claim':'All records reconstructed from uploaded file with original narratives and full review fragments preserved; code guards and roles are syntactic candidates only, not independently proven semantic judgments.'}
    (root/'quality_report.json').write_text(json.dumps(info,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(info,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
