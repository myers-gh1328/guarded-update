#!/usr/bin/env python3
"""Build an inactive exact-Git helper source artifact. Never installs or enables.

Archive integrity is not trusted release provenance. PR artifacts are review
only; target compatibility, privileged provisioning and activation are separate.
"""
import ast
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parents[1]
BUILDER='scripts/package-inventory-helper.py'
ENTRY='scripts/inventory_refresh_root_entry.py'
DOC='docs/inventory-refresh-contract.md'
LIB='libexec/command-center-inventory-refresh/'
INSTALL='/usr/local/'+LIB
ARCHIVE='command-center-inventory-metadata-helper.tar.gz'
EXPECTED_MODULES=('inventory_refresh_protocol','inventory_refresh_receipt','inventory_refresh_state','inventory_refresh_storage',
    'inventory_refresh_status','inventory_refresh_observation','inventory_refresh_cached_observation',
    'inventory_refresh_channel','inventory_refresh_guardian','inventory_refresh_observer','inventory_refresh_entry',
    'inventory_refresh_unit_status','inventory_refresh_service','inventory_refresh_policy',
    'inventory_refresh_policy_admission','inventory_refresh_materialized_policy','inventory_refresh_worker_service',
    'inventory_refresh_resources','inventory_refresh_materializer','inventory_refresh_writer_exclusion',
    'inventory_refresh_io','inventory_refresh_coordinator','inventory_refresh_contention','inventory_refresh_transaction',
    'inventory_refresh_observation_transaction','inventory_refresh_dispatch','inventory_refresh_runtime')


def require(condition):
    if not condition:raise ValueError('Inactive helper artifact unavailable')


def git(repo,*args):
    result=subprocess.run(('git','-c','core.fsmonitor=false',*args),cwd=repo,
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20)
    require(result.returncode==0);return result.stdout


def blob(repo,commit,path,limit):
    raw=git(repo,'ls-tree','-z',commit,'--',path)
    require(len(raw)<1024 and raw.endswith(b'\0') and raw.count(b'\0')==1)
    metadata,separator,actual=raw[:-1].partition(b'\t');parts=metadata.split()
    require(separator and actual==path.encode() and len(parts)==3 and parts[0] in (b'100644',b'100755') and
        parts[1]==b'blob' and re.fullmatch(rb'[0-9a-f]{40}',parts[2]) is not None)
    size=git(repo,'cat-file','-s',parts[2].decode()).strip()
    require(re.fullmatch(rb'[1-9][0-9]{0,7}',size) is not None and int(size)<=limit)
    data=git(repo,'cat-file','blob',parts[2].decode());require(len(data)==int(size));return data


def source_mapping(raw):
    tree=ast.parse(raw)
    assignments=[node for node in tree.body if isinstance(node,ast.Assign) and
        any(isinstance(target,ast.Name) and target.id=='SOURCES' for target in node.targets)]
    require(len(assignments)==1)
    # Admit only this fixed literal expression; never evaluate project code.
    expected=ast.parse("tuple((name,'guardian.py' if name=='inventory_refresh_guardian' else name+'.py') for name in "+repr(EXPECTED_MODULES)+")",mode='eval').body
    require(ast.dump(assignments[0].value)==ast.dump(expected))
    require(len(set(EXPECTED_MODULES))==len(EXPECTED_MODULES))
    return {LIB+('guardian.py' if name=='inventory_refresh_guardian' else name+'.py'):'scripts/'+name+'.py'
        for name in EXPECTED_MODULES}


def contents(repo):
    commit=git(repo,'rev-parse','--verify','HEAD^{commit}').decode().strip()
    require(re.fullmatch('[0-9a-f]{40}',commit) is not None)
    entry=blob(repo,commit,ENTRY,65536);mapping=source_mapping(entry)
    mapping.update({LIB+'coordinator.py':ENTRY,LIB+'worker.py':'scripts/inventory_refresh_worker.py',
        LIB+'observation-native.py':'scripts/inventory_refresh_entry.py',
        LIB+'observation-guardian.py':'scripts/inventory_refresh_entry.py',
        'share/doc/command-center-inventory-refresh/contract.md':DOC})
    builder=blob(repo,commit,BUILDER,65536)
    paths=sorted(set(mapping.values())|{BUILDER})
    # Compare the tested worktree with the one pinned commit, never mutable HEAD.
    git(repo,'diff','--quiet','--no-ext-diff','--no-textconv',commit,'--',*paths)
    data={name:blob(repo,commit,path,262144 if path==DOC else 65536) for name,path in mapping.items()}
    require(sum(len(data[LIB+('guardian.py' if name=='inventory_refresh_guardian' else name+'.py')]) for name in EXPECTED_MODULES)<=512*1024)
    require(data[LIB+'coordinator.py']==entry and
        data[LIB+'observation-native.py']==data[LIB+'observation-guardian.py']==data[LIB+'inventory_refresh_entry.py'])
    require(sum(map(len,data.values()))<=2*1024*1024)
    for name in data:
        require(not name.startswith('/') and all(part not in ('','..','.') for part in name.split('/')))
    manifest={'schema_version':1,'application':'command-center-inventory-metadata-helper','source_commit':commit,
        'build_script_sha256':hashlib.sha256(builder).hexdigest(),'python_language_floor':'3.10',
        'public_status_schema':1,'private_journal_schema':3,'installs_or_enables_services':False,
        'files':[{'path':name,'install_path':INSTALL+name[len(LIB):] if name.startswith(LIB) else None,
            'sha256':hashlib.sha256(value).hexdigest(),'size':len(value),'mode':'0444','uid':0,'gid':0}
            for name,value in sorted(data.items())]}
    data['manifest.json']=(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n').encode()
    return commit,data


def identity(info):return info.st_dev,info.st_ino


def write(directory,name,data,owned):
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
    try:
        owned.append((directory,name,identity(os.fstat(fd))))
        offset=0
        while offset<len(data):
            count=os.write(fd,data[offset:]);require(count>0);offset+=count
        os.fsync(fd)
    finally:os.close(fd)


def build(repo,output):
    """Build-only destination, not part of the privileged runtime interface."""
    stage=None;final=None;parent=None;stage_fd=None;final_fd=None;owned=[];directories=[]
    try:
        commit,data=contents(Path(repo))  # Validate complete immutable closure first.
        buffer=io.BytesIO()
        with gzip.GzipFile(fileobj=buffer,mode='wb',filename='',mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w',format=tarfile.USTAR_FORMAT) as archive:
                for name,value in sorted(data.items()):
                    member=tarfile.TarInfo(name);member.size=len(value);member.mode=0o444
                    member.uid=member.gid=member.mtime=0;member.uname=member.gname='root'
                    archive.addfile(member,io.BytesIO(value))
        raw=buffer.getvalue();require(len(raw)<=2*1024*1024)
        checksum=(hashlib.sha256(raw).hexdigest()+'  '+ARCHIVE+'\n').encode()
        output=Path(output);output.mkdir(mode=0o700,parents=True,exist_ok=True)
        parent=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        info=os.fstat(parent);require(info.st_uid==os.getuid() and not info.st_mode&0o077)
        stage_path=Path(tempfile.mkdtemp(prefix='.helper-stage-',dir=output));stage=stage_path.name
        stage_fd=os.open(stage,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        directories.append((stage,stage_fd,identity(os.fstat(stage_fd))))
        write(stage_fd,ARCHIVE,raw,owned);write(stage_fd,ARCHIVE+'.sha256',checksum,owned);os.fsync(stage_fd)
        final='helper-'+commit;os.mkdir(final,0o700,dir_fd=parent)
        final_fd=os.open(final,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        directories.append((final,final_fd,identity(os.fstat(final_fd))))
        for name in (ARCHIVE,ARCHIVE+'.sha256'):
            expected=identity(os.stat(name,dir_fd=stage_fd,follow_symlinks=False))
            os.link(name,name,src_dir_fd=stage_fd,dst_dir_fd=final_fd,follow_symlinks=False)
            owned.append((final_fd,name,expected))
        os.fsync(final_fd);os.fsync(parent)
        # Successful generation is retained; staged hardlinks alone are removed.
        owned=[record for record in owned if record[0]!=final_fd]
        directories=[record for record in directories if record[0]!=final]
        return output/final
    except BaseException:
        raise ValueError('Inactive helper artifact build failed') from None
    finally:
        failed=False
        for directory,name,expected in reversed(owned):
            try:
                named=os.stat(name,dir_fd=directory,follow_symlinks=False)
                if identity(named)==expected:os.unlink(name,dir_fd=directory)
            except FileNotFoundError:pass
            except OSError:failed=True
        if parent is not None:
            for name,fd,expected in reversed(directories):
                try:
                    if identity(os.stat(name,dir_fd=parent,follow_symlinks=False))==expected:os.rmdir(name,dir_fd=parent)
                except FileNotFoundError:pass
                except OSError:failed=True
        for fd in (final_fd,stage_fd,parent):
            if fd is not None:
                try:os.close(fd)
                except OSError:failed=True
        if failed:raise ValueError('Inactive helper artifact cleanup unconfirmed') from None


def main():
    try:
        require(len(sys.argv)==2)
        destination=build(ROOT,sys.argv[1]);print(str(destination));return 0
    except BaseException:
        print('Inactive helper artifact build unavailable',file=sys.stderr);return 1


if __name__=='__main__':sys.exit(main())
