from ctypes import CDLL, c_char_p, c_bool, POINTER
from pprint import pprint

MOSQ_ACL_NONE = 0
MOSQ_ACL_READ = 1
MOSQ_ACL_WRITE = 2

libmosquitto = CDLL('libmosquitto.so')
libmosquitto.mosquitto_topic_matches_sub.argtypes = [c_char_p, c_char_p, POINTER(c_bool)]

def topic_matches_sub(sub, topic):
    res = c_bool()
    libmosquitto.mosquitto_topic_matches_sub(sub, topic, res)
    return res.value

def plugin_init(opts):
    print 'plugin_init'
    pprint(opts)

def plugin_cleanup():
    print 'plugin_cleanup'

def unpwd_check(username, password):
    print 'unpwd_check', username, password
    return True

def acl_check(clientid, username, topic, access):
    print 'acl_check', topic_matches_sub('/#', topic)
    if access == MOSQ_ACL_READ:
        print 'acl_check READ', clientid, username, topic, access
    elif access == MOSQ_ACL_WRITE:
        print 'acl_check WRITE', clientid, username, topic, access
    return True

def security_init(opts, reload):
    print 'security_init', reload
    pprint(opts)

def security_cleanup(reload):
    print 'security_cleanup', reload
