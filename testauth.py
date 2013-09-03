from pprint import pprint

def plugin_init(opts):
    print 'plugin_init'
    pprint(opts)

def unpwd_check(username, password):
    print username, password
    return True
