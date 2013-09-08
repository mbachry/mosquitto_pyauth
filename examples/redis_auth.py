# Example Redis authentication
#
# Run from command line to set password and acl, for example:
#
#   python redis_auth.py foo foobar '/foo/#'
#
# Syntax:
#
#   python redis_auth.py <username> <password> <allowed topic>

import hashlib
from ctypes import CDLL, c_char_p, c_bool, POINTER
import redis

libmosquitto = CDLL('libmosquitto.so')
libmosquitto.mosquitto_topic_matches_sub.argtypes = [c_char_p, c_char_p, POINTER(c_bool)]

redis_conn = None

def topic_matches_sub(sub, topic):
    res = c_bool()
    libmosquitto.mosquitto_topic_matches_sub(sub, topic, res)
    return res.value

def plugin_init(opts):
    global redis_conn
    conf = dict(opts)
    redis_host = conf.get('redis_host', '127.0.0.1')
    redis_port = conf.get('redis_port', 6379)
    redis_conn = redis.StrictRedis(redis_host, redis_port)
    print 'redis initialized', redis_host, redis_port

def unpwd_check(username, password):
    val = redis_conn.hget('mosq.' + username, 'auth')
    if not val:
        print 'AUTH: no such user:', username
        return False
    salt, hashed = val.split(':')
    check = hashlib.sha1(salt + password).hexdigest()
    ok = (check == hashed)
    print 'AUTH: user=%s, password matches = %s' % (username, ok)
    return ok

def acl_check(clientid, username, topic, access):
    pat = redis_conn.hget('mosq.' + username, 'acl')
    if not pat:
        print 'ACL: no such user:', username
        return False
    matches = topic_matches_sub(pat, topic)
    print 'ACL: user=%s topic=%s, matches = %s' % (username, topic, matches)
    return matches


if __name__ == '__main__':
    import random
    import string
    import sys
    try:
        username = sys.argv[1]
        password = sys.argv[2]
        acl_topic = sys.argv[3]
    except IndexError:
        sys.exit('redis_auth <username> <password> <allowed topic>')
    salt = ''.join(c for _ in range(6) for c in random.choice(string.ascii_letters))
    hashed = hashlib.sha1(salt + password).hexdigest()
    conn = redis.StrictRedis()
    print 'HSET', 'mosq.' + username, 'auth', salt + ':' + hashed
    conn.hset('mosq.' + username, 'auth', salt + ':' + hashed)
    print 'HSET', 'mosq.' + username, 'acl', acl_topic
    conn.hset('mosq.' + username, 'acl', acl_topic)
    print '%s: password set successfully' % username
