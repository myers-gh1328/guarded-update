"""Journal/cache/status coordination; no command, path or OS execution interface.

The fixed runtime must hold the root journal lock and supply current boot,
current admitted policy and a manifest from an actual held Store lease. This
module does not acquire native observation or manufacture physical evidence.
"""
from inventory_refresh_state import boot, hexadecimal, checked_timestamp, REASONS
from inventory_refresh_status import PublicStatus
from inventory_refresh_storage import MAX_FILES
from inventory_refresh_receipt import observation as validate_observation


def _cache_metadata(manifest):
    if manifest is None:
        return None
    if (type(manifest) is not dict or set(manifest)!={'schema_version','cache_generation',
            'policy_generation','successful_checked_at','files'} or
            type(manifest['schema_version']) is not int or manifest['schema_version']!=1 or
            not hexadecimal(manifest['cache_generation'],32) or
            not hexadecimal(manifest['policy_generation'],64) or
            type(manifest['files']) is not list or len(manifest['files'])>MAX_FILES):
        raise ValueError('Invalid admitted inventory cache metadata')
    checked_timestamp(manifest['successful_checked_at'])
    return {key:manifest[key] for key in ('cache_generation','policy_generation','successful_checked_at')}


def publish_current_status(journal,publisher,*,boot_id,current_policy,manifest,
                           observation_lease=None,observation_receipt=None,operational_health=None):
    """Publish a fresh projection under the same held, reconciled root journal.

    Prior valid cache metadata is independent of the current refresh attempt.
    Synthetic health failures are uncorrelated: they never rewrite an immutable
    helper result under an old nonce. A client must not merge such health into
    a previously frozen correlated proof.
    """
    journal._locked()
    if publisher._journal is not journal:
        raise ValueError('Inventory status must share its coordination journal')
    if not boot(boot_id) or current_policy is not None and not hexadecimal(current_policy,64):
        raise ValueError('Invalid admitted inventory status context')
    if operational_health is not None and (type(operational_health) is not str or operational_health not in REASONS):
        raise ValueError('Invalid static inventory operational health')
    # Never accept a cached snapshot, particularly across a failed save/barrier.
    snapshot=journal.snapshot()
    accepted=snapshot['last_observation']
    retained_receipt=None if accepted is None else accepted['receipt']
    if observation_receipt is not None:
        if validate_observation(observation_receipt,True)!=retained_receipt:
            raise ValueError('Observation status requires its durable accepted receipt')
    observation_receipt=retained_receipt
    cache=_cache_metadata(manifest)
    success=snapshot['last_success']
    available=(cache is not None and success is not None and current_policy is not None and
        success['attempt']['boot_id']==boot_id and
        success['attempt']['cache_generation']==cache['cache_generation'] and
        success['attempt']['policy_generation']==cache['policy_generation']==current_policy and
        success['successful_checked_at']==cache['successful_checked_at'])
    refresh=snapshot['capabilities']['refresh']
    record=refresh['active'] if refresh['active'] is not None else refresh['terminal']
    uncertain=snapshot['unconfirmed'] or record is not None and record['phase']=='unconfirmed'
    health=None
    if uncertain:
        health='cleanup_unconfirmed'
    elif current_policy is None:
        health='policy_unsupported'
    elif record is None:
        health='cache_unavailable'
    elif record['policy_generation']!=current_policy:
        health='policy_changed'
    elif record['phase']=='succeeded' and not available:
        health='cache_unavailable'
    if health is None:health=operational_health
    if observation_lease is not None and (health is not None or not available or
            type(observation_lease) is not dict or observation_lease.get('boot_id')!=boot_id):
        raise ValueError('Unavailable inventory state cannot grant observation')
    attempt=None
    if health is None:
        attempt={key:record[key] for key in ('correlator','helper_sequence','boot_id',
                 'accepted_boottime_ms','started_boottime_ms','finished_boottime_ms')}
        if record['phase']=='deferred':
            attempt['finished_boottime_ms']=record['decision_boottime_ms']
    value={'schema_version':1,'operation_nonce':record['correlator'] if health is None else None,
           'phase':record['phase'] if health is None else 'unconfirmed',
           'reason':record['reason'] if health is None else health,
           'policy_generation':current_policy,
           'cache_generation':cache['cache_generation'] if available else None,
           'successful_checked_at':cache['successful_checked_at'] if available else None,
           'started_at':None,'finished_at':None,'attempt':attempt,
           'observation_lease':observation_lease,'observation_receipt':observation_receipt}
    status=PublicStatus.create(value)
    publisher.publish(status)
