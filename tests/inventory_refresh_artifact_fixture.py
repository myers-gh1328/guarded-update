"""Read-only archive admission for disposable native CI fixtures only.

This never installs, executes a generator/runtime or grants production authority.
Expected USTAR is reconstructed independently from fixed selected Git inputs.
"""
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import zlib

ARCHIVE='command-center-inventory-metadata-helper.tar.gz'
LIB='libexec/command-center-inventory-refresh/'
INSTALL='/usr/local/'+LIB
ROOT_MODULES=('inventory_refresh_protocol','inventory_refresh_receipt','inventory_refresh_state','inventory_refresh_storage',
    'inventory_refresh_status','inventory_refresh_observation','inventory_refresh_cached_observation',
    'inventory_refresh_channel','inventory_refresh_guardian','inventory_refresh_observer','inventory_refresh_entry',
    'inventory_refresh_unit_status','inventory_refresh_service','inventory_refresh_policy',
    'inventory_refresh_policy_admission','inventory_refresh_materialized_policy','inventory_refresh_worker_service',
    'inventory_refresh_resources','inventory_refresh_materializer','inventory_refresh_writer_exclusion',
    'inventory_refresh_io','inventory_refresh_coordinator','inventory_refresh_contention','inventory_refresh_transaction',
    'inventory_refresh_observation_transaction','inventory_refresh_dispatch','inventory_refresh_runtime')
REPORTER_MODULES=('inventory_refresh_protocol','inventory_refresh_receipt','inventory_refresh_state','inventory_refresh_storage',
    'inventory_refresh_status','inventory_refresh_observation','inventory_refresh_resources','inventory_refresh_reporter_resources',
    'inventory_refresh_reporter_parent','inventory_refresh_reader_tools','inventory_refresh_reader_session',
    'inventory_refresh_reporter_io','inventory_refresh_reporter_environment','inventory_refresh_io',
    'inventory_refresh_reporter_runtime','inventory_refresh_reporter_protocol','inventory_refresh_reporter_pipe','inventory_refresh_reporter_dialogue')
BUILDER='scripts/package-inventory-helper.py'
ENTRY='scripts/inventory_refresh_root_entry.py'
GENERATOR='scripts/inventory_refresh_reporter_build.py'
TEMPLATE='scripts/inventory_refresh_reporter_template.py'
DOC='docs/inventory-refresh-contract.md'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'}


def require(condition):
    if not condition:raise ValueError('Native fixture artifact admission unavailable')


def _metadata(item):
    return (item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid,item.st_nlink,
        item.st_size,item.st_mtime_ns,item.st_ctime_ns)


def _read(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=limit)
        raw=bytearray()
        while True:
            chunk=os.read(fd,min(65536,limit+1-len(raw)))
            if not chunk:break
            raw.extend(chunk);require(len(raw)<=limit)
        require(len(raw)==before.st_size and _metadata(before)==_metadata(os.fstat(fd))==_metadata(os.stat(path,follow_symlinks=False)))
        return bytes(raw)
    finally:os.close(fd)


def _git(repo,*arguments):
    result=subprocess.run(['/usr/bin/git','--no-replace-objects','-c','core.fsmonitor=false',
        '-c','safe.directory='+str(Path(repo).resolve()),*arguments],cwd=repo,env=ENV,stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
    require(result.returncode==0 and len(result.stdout)<=2*1024*1024)
    return result.stdout


def _blob(repo,commit,path):
    raw=_git(repo,'ls-tree','-z',commit,'--',path)
    require(len(raw)<1024 and raw.endswith(b'\0') and raw.count(b'\0')==1)
    metadata,separator,actual=raw[:-1].partition(b'\t');parts=metadata.split()
    require(separator and actual==path.encode() and len(parts)==3 and parts[0] in (b'100644',b'100755') and
        parts[1]==b'blob' and re.fullmatch(rb'[0-9a-f]{40}',parts[2]) is not None)
    size=_git(repo,'cat-file','-s',parts[2].decode()).strip();limit=262144 if path==DOC else 65536
    require(re.fullmatch(rb'[1-9][0-9]{0,7}',size) is not None and int(size)<=limit)
    data=_git(repo,'cat-file','blob',parts[2].decode());require(len(data)==int(size));return data


def _literal(raw,name,expected):
    tree=ast.parse(raw)
    nodes=[node for node in tree.body if type(node) is ast.Assign and len(node.targets)==1 and
        type(node.targets[0]) is ast.Name and node.targets[0].id==name]
    require(len(nodes)==1 and sum(isinstance(node,ast.Name) and isinstance(node.ctx,ast.Store) and node.id==name for node in ast.walk(tree))==1)
    require(ast.dump(nodes[0].value)==ast.dump(ast.parse(repr(expected),mode='eval').body))


def _generated(entry,template):
    text=entry.decode('utf-8');tree=ast.parse(text);segments=[]
    for name,kind in (('_require',ast.FunctionDef),('_stable',ast.FunctionDef),('_directory',ast.FunctionDef),('RootSources',ast.ClassDef)):
        nodes=[node for node in ast.walk(tree) if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and node.name==name]
        require(len(nodes)==1 and type(nodes[0]) is kind and nodes[0] in tree.body and not nodes[0].decorator_list)
        segments.append(ast.get_source_segment(text,nodes[0]))
    value=template.decode('utf-8');markers=('# @FIXED_SOURCE_MODULES@','# @FIXED_SOURCE_LOADER@')
    require(all(value.count(marker)==1 and marker in value.splitlines() for marker in markers))
    value=value.replace(markers[0],'SOURCES='+repr(tuple((name,name+'.py') for name in REPORTER_MODULES)))
    raw=value.replace(markers[1],'\n\n'.join(segments)).encode('utf-8');require(0<len(raw)<=65536)
    _literal(raw,'SOURCES',tuple((name,name+'.py') for name in REPORTER_MODULES))
    return raw


def expected_files(repo):
    commit=_git(repo,'rev-parse','--verify','HEAD^{commit}').decode().strip();require(re.fullmatch('[0-9a-f]{40}',commit) is not None)
    mapping={LIB+('guardian.py' if name=='inventory_refresh_guardian' else name+'.py'):'scripts/'+name+'.py' for name in ROOT_MODULES}
    for name in REPORTER_MODULES:
        target=LIB+name+'.py';source='scripts/'+name+'.py'
        require(target not in mapping or mapping[target]==source);mapping[target]=source
    mapping.update({LIB+'coordinator.py':ENTRY,LIB+'worker.py':'scripts/inventory_refresh_worker.py',
        LIB+'observation-native.py':'scripts/inventory_refresh_entry.py',LIB+'observation-guardian.py':'scripts/inventory_refresh_entry.py',
        'share/doc/command-center-inventory-refresh/contract.md':DOC})
    inputs={path:_blob(repo,commit,path) for path in sorted(set(mapping.values())|{BUILDER,GENERATOR,TEMPLATE})}
    _literal(inputs[BUILDER],'EXPECTED_MODULES',ROOT_MODULES)
    _literal(inputs[BUILDER],'EXPECTED_REPORTER_MODULES',REPORTER_MODULES)
    _literal(inputs[GENERATOR],'MODULES',REPORTER_MODULES)
    data={name:inputs[path] for name,path in mapping.items()}
    generated=_generated(inputs[ENTRY],inputs[TEMPLATE]);data[LIB+'reporter.py']=generated
    require(sum(len(data[LIB+('guardian.py' if name=='inventory_refresh_guardian' else name+'.py')]) for name in ROOT_MODULES)<=512*1024 and
        sum(len(data[LIB+name+'.py']) for name in REPORTER_MODULES)<=512*1024 and sum(map(len,data.values()))<=2*1024*1024)
    digest=lambda raw:hashlib.sha256(raw).hexdigest()
    recipe=dict(loader_source_sha256=digest(inputs[ENTRY]),template_sha256=digest(inputs[TEMPLATE]),
        generator_sha256=digest(inputs[GENERATOR]),closure_sha256=digest(json.dumps(tuple((name,name+'.py') for name in REPORTER_MODULES),separators=(',',':')).encode('ascii')),
        generated_entry_sha256=digest(generated),entry_path=LIB+'reporter.py',module_names=list(REPORTER_MODULES))
    manifest=dict(schema_version=1,application='command-center-inventory-metadata-helper',source_commit=commit,
        build_script_sha256=digest(inputs[BUILDER]),python_language_floor='3.10',public_status_schema=1,private_journal_schema=3,
        installs_or_enables_services=False,reporter_bootstrap=recipe,files=[dict(path=name,install_path=INSTALL+name[len(LIB):] if name.startswith(LIB) else None,
            sha256=digest(value),size=len(value),mode='0444',uid=0,gid=0) for name,value in sorted(data.items())])
    data['manifest.json']=(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n').encode()
    return commit,data


def ustar(data):
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w',format=tarfile.USTAR_FORMAT) as target:
        for name,raw in sorted(data.items()):
            item=tarfile.TarInfo(name);item.size=len(raw);item.mode=0o444;item.uid=item.gid=item.mtime=0;item.uname=item.gname='root'
            target.addfile(item,io.BytesIO(raw))
    result=buffer.getvalue();require(len(result)<=4*1024*1024)
    return result


def verify_archive(repo,archive):
    try:
        archive=Path(archive);require(archive.name==ARCHIVE)
        raw=_read(archive,2*1024*1024);sidecar=_read(archive.with_name(ARCHIVE+'.sha256'),256)
        digest=hashlib.sha256(raw).hexdigest();require(sidecar==(digest+'  '+ARCHIVE+'\n').encode('ascii'))
        stream=zlib.decompressobj(16+zlib.MAX_WBITS);expanded=stream.decompress(raw,4*1024*1024+1)
        require(len(expanded)<=4*1024*1024 and stream.eof and not stream.unused_data and not stream.unconsumed_tail)
        commit,data=expected_files(repo)
        # Exact deterministic USTAR comparison rejects hidden trailing members,
        # nonzero end padding, duplicate JSON keys/rows and every alias/extra.
        require(expanded==ustar(data))
        return dict(source_commit=commit,archive_sha256=digest,entry_sha256=hashlib.sha256(data[LIB+'reporter.py']).hexdigest(),
            reporter_modules=REPORTER_MODULES,files=data)
    except (OSError,ValueError,TypeError,UnicodeError,SyntaxError,RecursionError,zlib.error):
        raise ValueError('Native fixture artifact admission unavailable') from None
