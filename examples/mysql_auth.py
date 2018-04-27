#!/usr/bin/env python
# Example MySQL authentication
# 
# To use, add this to mosquitto.conf:
# 
#   auth_plugin /path/to/auth_plugin_pyauth.so
#   auth_opt_pyauth_module mysql_auth
#   auth_opt_mysql_host MySQL_hostname
#   auth_opt_mysql_user MySQL_username
#   auth_opt_mysql_password MySQL_password
#   auth_opt_mysql_database MySQL_database
#   auth_opt_mysql_port MySQL_port
# 
# Example:
# 
#   auth_plugin /usr/mosquitto_pyauth/auth_plugin_pyauth.so
#   auth_opt_pyauth_module mysql_auth
#   auth_opt_mysql_host 127.0.0.1
#   auth_opt_mysql_user root
#   auth_opt_mysql_password password
#   auth_opt_mysql_database mydb
#   auth_opt_mysql_port 3306
# 
# Create the MySQL table, for example:
# 
#   CREATE DATABASE IF NOT EXISTS mydb;
#   USE mydb;
#   CREATE TABLE IF NOT EXISTS users (
#       username VARCHAR(256) NOT NULL,
#       auth VARCHAR(1024) NOT NULL,
#       acl VARCHAR(256),
#       PRIMARY KEY(username));
# 
# Then start the daemon with the PYTHONPATH variable, for example:
# 
#   export PYTHONPATH=/path/to/this/file/; mosquitto -c /path/to/mosquitto.conf
# 
# Run from command line to set password and acl, for example:
# 
#   python mysql_auth.py foo foobar '/foo/#'
# 
# Syntax:
# 
#   python mysql_auth.py <username> <password> <allowed topic>

import hashlib
import pymysql
import encodings.idna

mysql_conn = None

def plugin_init(opts):
    # Import this inside every module that logs because we cannot import it if __name__ == '__main__'
    import mosquitto_auth
    
    global mysql_conn
    mysql = conn_opts(opts)
    mysql_conn = pymysql.connect(**mysql)
    mosquitto_auth.log(mosquitto_auth.LOG_DEBUG, 'mysql initialized %s %s' % (mysql['host'], mysql['port']))

def conn_opts(opts):
    ''' Input the opts tuple, output the connection options '''
    mysql = {}
    conf = dict(opts)
    mysql['host'] = conf.get('mysql_host', '127.0.0.1')
    mysql['user'] = conf.get('mysql_user', 'root')
    mysql['password'] = conf.get('mysql_password', 'password')
    mysql['database'] = conf.get('mysql_database', 'mydb')
    mysql['port'] = int(conf.get('mysql_port', 3306))
    return mysql

def get_opts(conf_file='/etc/mosquitto/mosquitto.conf'):
    ''' Get the options from the config file '''
    opts = []
    with open(conf_file) as conf:
        for row in conf:
            if row.startswith('auth_opt_'):
                key, val = row.split()[0].replace('auth_opt_', ''), row.split()[1]
                if key == 'pyauth_module':
                    # Skip this one
                    continue
                opts.append((key, val))
    return tuple(opts)

def unpwd_check(username, password):
    import mosquitto_auth
    
    with mysql_conn.cursor() as cursor:
        sql = "SELECT `auth` FROM `users` WHERE `username`=%s"
        cursor.execute(sql, (username,))
        val = cursor.fetchone()
    if not val:
        mosquitto_auth.log(mosquitto_auth.LOG_DEBUG, 'AUTH: no such user: %s' % username)
        return False
    salt, hashed = val[0].split(':')
    check = hashlib.sha1(salt.encode() + password.encode()).hexdigest().encode()
    ok = (check == hashed.encode())
    
    mosquitto_auth.log(mosquitto_auth.LOG_DEBUG, 'AUTH: user=%s, password matches=%s' % (username, ok,))
    return ok

def acl_check(clientid, username, topic, access):
    import mosquitto_auth
    
    if username is None:
        mosquitto_auth.log(mosquitto_auth.LOG_DEBUG, 'AUTH required')
        return False
    with mysql_conn.cursor() as cursor:
        sql = "SELECT `acl` FROM `users` WHERE `username`=%s"
        cursor.execute(sql, (username,))
        pat = cursor.fetchone()[0]
    if not pat:
        mosquitto_auth.log(mosquitto_auth.LOG_DEBUG, 'ACL: no such user: %s' % username)
        return False
    matches = mosquitto_auth.topic_matches_sub(pat, topic)
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
        sys.exit('mysql_auth <username> <password> <allowed topic>')
    salt = ''.join(c for _ in range(6) for c in random.choice(string.ascii_letters))
    hashed = hashlib.sha1(salt.encode() + password.encode()).hexdigest()
    
    conn = pymysql.connect(**conn_opts(get_opts()))
    with conn.cursor() as cursor:
        cursor.execute('INSERT INTO `users` (`username`, `auth`) VALUES (%s, %s);', (username, salt + ':' + hashed,))
        print(cursor._last_executed)
        cursor.execute('UPDATE `users` SET `acl` = %s WHERE `username`=%s;', (acl_topic, username,))
        print(cursor._last_executed)
        conn.commit()
        print('%s: password set successfully' % username)
        conn.close()
