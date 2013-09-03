from pprint import pprint

MOSQ_ACL_NONE = 0
MOSQ_ACL_READ = 1
MOSQ_ACL_WRITE = 2

def plugin_init(opts):
    print 'plugin_init'
    pprint(opts)

def plugin_cleanup():
    print 'plugin_cleanup'

def unpwd_check(username, password):
    print 'unpwd_check', username, password
    return True

def acl_check(clientid, username, topic, access):
    if access == MOSQ_ACL_READ:
        print 'acl_check READ', clientid, username, topic, access
    elif access == MOSQ_ACL_WRITE:
        print 'acl_check WRITE', clientid, username, topic, access
    return True
