"""Internal candidate consistency only; no enrollment or launch authority.

The supplied server fields and public bytes are untrusted. This module does not
authenticate them, validate a key, own a maintenance window, publish anything,
or make the Root journal and marker observations atomic.
"""
import hashlib
import re
import time

from inventory_refresh_enrollment_marker import _read_from


class CandidateError(ValueError):
    pass


def _candidate_from(journal,root_fd,owner,group,deadline,server,spki,expected_epoch):
    """Compare caller data with a locked journal and historical marker."""
    try:
        if type(server) is not dict or set(server)!={'device_id','fleet','boundary','enrollment_id','key_id','fingerprint'}:
            raise CandidateError('Binding candidate unavailable')
        device=server['device_id'];fleet=server['fleet'];boundary=server['boundary']
        enrollment=server['enrollment_id'];key=server['key_id'];fingerprint=server['fingerprint']
        if (type(device) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',device) is None or
                type(fleet) is not str or fleet not in ('personal','business') or type(boundary) is not str or
                not boundary.strip() or len(boundary.encode('utf-16-le'))//2>256 or re.search(r'[\x00-\x1f\x7f]',boundary) is not None or
                type(enrollment) is not str or re.fullmatch(r'[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}',enrollment) is None or
                type(key) is not str or re.fullmatch(r'[A-Za-z0-9_-]{1,64}',key) is None or
                type(fingerprint) is not str or re.fullmatch(r'[a-f0-9]{64}',fingerprint) is None or
                type(expected_epoch) is not str or re.fullmatch(r'[a-f0-9]{32}',expected_epoch) is None or
                type(spki) is not bytes or not 0<len(spki)<=4096):
            raise CandidateError('Binding candidate unavailable')
        observed=_read_from(root_fd,owner,group,deadline)
        counters=journal.counter_snapshot()
        if (observed!=enrollment or counters['root_epoch']!=expected_epoch or
                hashlib.sha256(spki).hexdigest()!=fingerprint or time.monotonic()>=deadline):
            raise CandidateError('Binding candidate unavailable')
        return {'schema_version':1,'device_id':device,'fleet':fleet,'boundary':boundary,
                'enrollment_id':enrollment,'key_id':key,'fingerprint':fingerprint,'root_epoch':expected_epoch}
    except (KeyError,TypeError,UnicodeError,ValueError,OSError):
        raise CandidateError('Binding candidate unavailable') from None
