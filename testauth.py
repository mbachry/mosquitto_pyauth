from pprint import pprint
import mosquitto_auth


def plugin_init(opts):
    print 'plugin_init'
    pprint(opts)

def plugin_cleanup():
    print 'plugin_cleanup'

def unpwd_check(username, password):
    print 'unpwd_check', username, password
    return True

def acl_check(clientid, username, topic, access):
    print 'acl_check', mosquitto_auth.topic_matches_sub('/#', topic)
    if access == mosquitto_auth.MOSQ_ACL_READ:
        print 'acl_check READ', clientid, username, topic, access
    elif access == mosquitto_auth.MOSQ_ACL_WRITE:
        print 'acl_check WRITE', clientid, username, topic, access
    return True

def psk_key_get(identity, hint):
    print 'psk_key_get', identity, hint
    return '0123456789'

def security_init(opts, reload):
    print 'security_init', reload
    pprint(opts)

def security_cleanup(reload):
    print 'security_cleanup', reload
