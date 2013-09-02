#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <Python.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>

struct pyauth_data {
    char *module_name;
    PyObject *module;
    PyObject *unpwd_check_func;
};

#define unused  __attribute__((unused))

#ifdef PYAUTH_DEBUG
__attribute__((format(1, 2)))
static void debug(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
#else
static void debug(const char *fmt unused, ...)
{
}
#endif


int mosquitto_auth_plugin_version(void)
{
    return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
    struct pyauth_data *data = calloc(1, sizeof(*data));
    assert(data != NULL);

    for (int i = 0; i < auth_opt_count; i++) {
        if (!strcmp(auth_opts[i].key, "pyauth_module")) {
            data->module_name = strdup(auth_opts[i].value);
            debug("pyauth_module = %s", data->module_name);
        }
    }
    if (data->module_name == NULL) {
        fprintf(stderr, "pyauth_module config param missing\n");
        exit(1);
    }

    Py_Initialize();

    data->module = PyImport_ImportModule(data->module_name);
    if (data->module == NULL) {
        fprintf(stderr, "failed to import module: %s\n", data->module_name);
        exit(1);
    }

    data->unpwd_check_func = PyObject_GetAttrString(data->module, "unpwd_check");

    *user_data = data;
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts unused, int auth_opt_count unused)
{
    struct pyauth_data *data = user_data;
    Py_DECREF(data->module);
    Py_XDECREF(data->unpwd_check_func);
    free(data->module_name);
    free(data);
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data unused, struct mosquitto_auth_opt *auth_opts unused, int auth_opt_count unused, bool reload unused)
{
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data unused, struct mosquitto_auth_opt *auth_opts unused, int auth_opt_count unused, bool reload unused)
{
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data unused, const char *clientid unused, const char *username unused, const char *topic unused, int access)
{
    if (access == MOSQ_ACL_READ) {
        return MOSQ_ERR_SUCCESS;
    }
    return MOSQ_ERR_ACL_DENIED;
}

int mosquitto_auth_unpwd_check(void *user_data unused, const char *username, const char *password)
{
    struct pyauth_data *data = user_data;

    if (username == NULL || password == NULL)
        return MOSQ_ERR_AUTH;

    debug("mosquitto_auth_unpwd_check: username=%s, password=%s", username, password);

    if (data->unpwd_check_func == NULL)
        return MOSQ_ERR_AUTH;

    PyObject *res = PyObject_CallFunction(data->unpwd_check_func, "ss", username, password);
    if (res == NULL) {
        PyErr_Print();
        return MOSQ_ERR_UNKNOWN;
    }
    int ok = PyObject_IsTrue(res);
    Py_DECREF(res);

    return ok ? MOSQ_ERR_SUCCESS : MOSQ_ERR_AUTH;
}

int mosquitto_auth_psk_key_get(void *user_data unused, const char *hint unused, const char *identity unused, char *key unused, int max_key_len unused)
{
    return MOSQ_ERR_AUTH;
}
