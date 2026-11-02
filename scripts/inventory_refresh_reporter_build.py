"""Build-only fixed reporter entry generation from selected immutable Git bytes.

No project source is executed. Artifact builder must bind these input bytes and
this generator to its selected commit; runtime accepts no generator inputs.
"""
import ast
import hashlib
import json

MODULES=('inventory_refresh_protocol','inventory_refresh_receipt','inventory_refresh_state','inventory_refresh_storage',
    'inventory_refresh_status','inventory_refresh_observation','inventory_refresh_resources','inventory_refresh_reporter_resources',
    'inventory_refresh_reporter_parent','inventory_refresh_reader_tools','inventory_refresh_reader_session',
    'inventory_refresh_reporter_io','inventory_refresh_reporter_environment','inventory_refresh_io',
    'inventory_refresh_reporter_runtime','inventory_refresh_reporter_protocol','inventory_refresh_reporter_pipe','inventory_refresh_reporter_dialogue')
HELPERS=('_require','_stable','_directory','RootSources')


def _require(condition):
    if not condition:raise ValueError('Fixed reporter entry generation unavailable')


def _signature(node,names,*,class_method=False,owner=False):
    _require(type(node) is ast.FunctionDef and node.returns is None and node.type_comment is None and not getattr(node,'type_params',()))
    expected=[ast.Name(id='classmethod',ctx=ast.Load())] if class_method else []
    _require([ast.dump(item) for item in node.decorator_list]==[ast.dump(item) for item in expected])
    arguments=node.args
    _require(not arguments.posonlyargs and arguments.vararg is None and arguments.kwarg is None and not arguments.defaults and
        [item.arg for item in arguments.args]==list(names) and all(item.annotation is None for item in arguments.args))
    _require([item.arg for item in arguments.kwonlyargs]==(['owner'] if owner else []) and
        all(item.annotation is None for item in arguments.kwonlyargs))
    _require([ast.dump(item) for item in arguments.kw_defaults]==([ast.dump(ast.Constant(value=0))] if owner else []))


def generate(loader_source,template_source):
    try:
        _require(type(loader_source) is bytes and 0<len(loader_source)<=65536 and
            type(template_source) is bytes and 0<len(template_source)<=65536)
        text=loader_source.decode('utf-8');template=template_source.decode('utf-8');tree=ast.parse(text)
        selected={}
        for name in HELPERS:
            nodes=[node for node in ast.walk(tree) if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and node.name==name]
            _require(len(nodes)==1 and nodes[0] in tree.body);selected[name]=nodes[0]
        _require(not any(isinstance(node,ast.Name) and isinstance(node.ctx,ast.Store) and node.id in HELPERS for node in ast.walk(tree)))
        for name,arguments in (('_require',('condition',)),('_stable',('info',)),('_directory',('info','owner'))):
            _signature(selected[name],arguments)
        source=selected['RootSources']
        _require(type(source) is ast.ClassDef and not source.decorator_list and not source.bases and not source.keywords and not getattr(source,'type_params',()))
        methods={'__init__':('self','directory'),'fixed':('cls',),'_verify':('self',),'execute':('self',),'close':('self',)}
        _require(len(source.body)==len(methods) and all(type(node) is ast.FunctionDef for node in source.body) and
            {node.name for node in source.body}==set(methods))
        for node in source.body:_signature(node,methods[node.name],class_method=node.name=='fixed',owner=node.name=='__init__')
        modules=tuple((name,name+'.py') for name in MODULES)
        markers=('# @FIXED_SOURCE_MODULES@','# @FIXED_SOURCE_LOADER@')
        _require(all(template.count(marker)==1 and marker in template.splitlines() for marker in markers))
        segments=[ast.get_source_segment(text,selected[name]) for name in HELPERS]
        _require(all(type(segment) is str and segment for segment in segments))
        generated=template.replace(markers[0],'SOURCES='+repr(modules)).replace(markers[1],'\n\n'.join(segments)).encode('utf-8')
        _require(len(generated)<=65536)
        rendered=generated.decode('utf-8');final=ast.parse(rendered);protected=set(HELPERS)|{'SOURCES'}
        for name,segment in zip(HELPERS,segments):
            definitions=[node for node in ast.walk(final) if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and node.name==name]
            _require(len(definitions)==1 and definitions[0] in final.body and ast.get_source_segment(rendered,definitions[0])==segment)
        _require(not any(isinstance(node,ast.Name) and isinstance(node.ctx,ast.Store) and node.id in HELPERS for node in ast.walk(final)))
        _require(not any(isinstance(node,ast.alias) and (node.asname or node.name.split('.')[0]) in protected or
            isinstance(node,ast.arg) and node.arg in protected for node in ast.walk(final)))
        assignments=[node for node in final.body if type(node) is ast.Assign and len(node.targets)==1 and
            type(node.targets[0]) is ast.Name and node.targets[0].id=='SOURCES']
        _require(len(assignments)==1 and sum(isinstance(node,ast.Name) and isinstance(node.ctx,ast.Store) and node.id=='SOURCES' for node in ast.walk(final))==1)
        _require(ast.dump(assignments[0].value)==ast.dump(ast.parse(repr(modules),mode='eval').body))
        compile(generated,'/usr/local/libexec/command-center-inventory-refresh/reporter.py','exec',dont_inherit=True)
        digest=lambda raw:hashlib.sha256(raw).hexdigest()
        return generated,dict(loader_source_sha256=digest(loader_source),template_sha256=digest(template_source),
            closure_sha256=digest(json.dumps(modules,separators=(',',':')).encode('ascii')),generated_entry_sha256=digest(generated))
    except (ValueError,TypeError,SyntaxError,UnicodeError,RecursionError):
        raise ValueError('Fixed reporter entry generation unavailable') from None
