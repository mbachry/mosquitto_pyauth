import mosquitto_auth


def plugin_init(opts):
    mosquitto_auth.log(
        mosquitto_auth.LOG_DEBUG,
        'plugin_init (opts: %r)' % (opts,)
    )


def plugin_cleanup():
    mosquitto_auth.log(mosquitto_auth.LOG_DEBUG, 'plugin_cleanup')


def unpwd_check(username, password):
    mosquitto_auth.log(
        mosquitto_auth.LOG_DEBUG,
        'unpwd_check (username: %s password: %s)' % (username, password)
    )

    return True


def acl_check(client_id, username, topic, access, payload):
    mosquitto_auth.log(
        mosquitto_auth.LOG_DEBUG,
        'acl_check %r' % (mosquitto_auth.topic_matches_sub('/#', topic))
    )

    if access == mosquitto_auth.MOSQ_ACL_READ:
        mosquitto_auth.log(
            mosquitto_auth.LOG_DEBUG,
            'acl_check READ (client_id: {} username: {} topic: {} access: {}, payload: {!r})'
            .format(client_id, username, topic, access, payload)
        )
    elif access == mosquitto_auth.MOSQ_ACL_SUBSCRIBE:
        mosquitto_auth.log(
            mosquitto_auth.LOG_DEBUG,
            'acl_check SUBSCRIBE (client_id: {} username: {} topic: {} access: {}, payload: {!r})'
            .format(client_id, username, topic, access, payload)
        )
    elif access == mosquitto_auth.MOSQ_ACL_WRITE:
        mosquitto_auth.log(
            mosquitto_auth.LOG_DEBUG,
            'acl_check WRITE (client_id: {} username: {} topic: {} access: {}, payload: {!r})'
            .format(client_id, username, topic, access, payload)
        )
    return True


def psk_key_get(identity, hint):
    mosquitto_auth.log(
        mosquitto_auth.LOG_DEBUG,
        'psk_key_get (identity: %s hint: %s)' % (identity, hint)
    )
    return '0123456789'


def security_init(opts, reload):
    mosquitto_auth.log(
        mosquitto_auth.LOG_DEBUG,
        'security_init (reload: %s, opts: %s)' % (reload, opts)
    )


def security_cleanup(reload):
    mosquitto_auth.log(
        mosquitto_auth.LOG_DEBUG,
        'security_cleanup (reload: %s)' % (reload)
    )
