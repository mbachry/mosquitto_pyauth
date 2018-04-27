#!/usr/bin/env python
# Example Redis authentication
# 
# To use, add this to mosquitto.conf:
# 
#   auth_plugin /path/to/auth_plugin_pyauth.so
#   auth_opt_pyauth_module redis_auth
# 
# Example:
# 
#   auth_plugin /usr/mosquitto_pyauth/auth_plugin_pyauth.so
#   auth_opt_pyauth_module redis_auth
#
# Then start the daemon with the PYTHONPATH variable, for example:
# 
#   export PYTHONPATH=/path/to/this/file/; mosquitto -c /path/to/mosquitto.conf
# 
# Run from command line to set password and acl, for example:
#
#   python redis_auth.py foo foobar '/foo/#'
#
# Syntax:
#
#   python redis_auth.py <username> <password> <allowed topic>

import hashlib
import redis
import encodings.idna

redis_conn = None

def plugin_init(opts):
    # Import this inside every module that logs because we cannot import it if __name__ == '__main__'
    import mosquitto_auth
    
    global redis_conn
    conf = dict(opts)
    redis_host = conf.get('redis_host', '127.0.0.1')
    redis_port = conf.get('redis_port', 6379)
    redis_conn = redis.StrictRedis(redis_host, redis_port)
    mosquitto_auth.log(mosquitto_auth.LOG_DEBUG, 'redis initialized %s %s' % (redis_host, redis_port,))

def unpwd_check(username, password):
    import mosquitto_auth
    
    val = redis_conn.hget('mosq.' + username, 'auth')
    if not val:
        mosquitto_auth.log(mosquitto_auth.LOG_DEBUG, 'AUTH: no such user: %s' % username)
        return False
    salt, hashed = val.split(b':')
    check = hashlib.sha1(salt + password.encode()).hexdigest().encode()
    ok = (check == hashed)
    mosquitto_auth.log(mosquitto_auth.LOG_DEBUG, 'AUTH: user=%s, password matches=%s' % (username, ok,))
    return ok

def acl_check(clientid, username, topic, access):
    import mosquitto_auth
    
    if username is None:
        mosquitto_auth.log(mosquitto_auth.LOG_DEBUG, 'AUTH required')
        return False
    pat = redis_conn.hget('mosq.' + username, 'acl')
    if not pat:
        mosquitto_auth.log(mosquitto_auth.LOG_DEBUG, 'ACL: no such user: %s' % username)
        return True
    matches = mosquitto_auth.topic_matches_sub(pat.decode(), topic)
    mosquitto_auth.log(mosquitto_auth.LOG_DEBUG, 'ACL: user=%s topic=%s, pat=%s, matches=%s' % (username, topic, pat, matches,))
    return matches


def psk_key_get(identity, hint):
    import mosquitto_auth
    
    mosquitto_auth.log(mosquitto_auth.LOG_DEBUG, 'psk_key_get %s %s' % (identity, hint,))
    return '0123456789'


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
    hashed = hashlib.sha1(salt.encode() + password.encode()).hexdigest()
    conn = redis.StrictRedis()
    print('HSET', 'mosq.' + username, 'auth', salt + ':' + hashed)
    conn.hset('mosq.' + username, 'auth', salt + ':' + hashed)
    print('HSET', 'mosq.' + username, 'acl', acl_topic)
    conn.hset('mosq.' + username, 'acl', acl_topic)
    print('%s: password set successfully' % username)