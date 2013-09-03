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
    PyObject *plugin_cleanup_func;
    PyObject *unpwd_check_func;
};

#define unused  __attribute__((unused))

#ifdef PYAUTH_DEBUG
__attribute__((format(printf, 1, 2)))
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

__attribute__((format(printf, 2, 3)))
static void die(bool print_exception, const char *fmt, ...)
{
    if (print_exception)
        PyErr_Print();
    va_list ap;
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

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
    if (data->module_name == NULL)
        die(false, "pyauth_module config param missing");

    Py_Initialize();

    data->module = PyImport_ImportModule(data->module_name);
    if (data->module == NULL)
        die(true, "failed to import module: %s", data->module_name);

    data->plugin_cleanup_func = PyObject_GetAttrString(data->module, "plugin_cleanup");
    data->unpwd_check_func = PyObject_GetAttrString(data->module, "unpwd_check");

    PyObject *init_func = PyObject_GetAttrString(data->module, "plugin_init");
    if (init_func != NULL) {
        PyObject *optlist = PyTuple_New(auth_opt_count - 1); /* -1 because of skipped "pyauth_module" */
        if (optlist == NULL)
            die(true, "python module initialization failed");

        int idx = 0;
        for (int i = 0; i < auth_opt_count; i++) {
            if (!strcmp(auth_opts[i].key, "pyauth_module"))
                continue;

            PyObject *elt = PyTuple_Pack(2,
                                         PyString_FromString(auth_opts[i].key),
                                         PyString_FromString(auth_opts[i].value));
            if (elt == NULL)
                die(true, "python module initialization failed");

            PyTuple_SET_ITEM(optlist, idx++, elt);
        }

        PyObject *res = PyObject_CallFunctionObjArgs(init_func, optlist, NULL);
        if (res == NULL)
                die(true, "python module initialization failed");
        Py_DECREF(res);

        Py_DECREF(optlist);
        Py_DECREF(init_func);
    }

    *user_data = data;
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts unused, int auth_opt_count unused)
{
    struct pyauth_data *data = user_data;

    if (data->plugin_cleanup_func != NULL) {
        PyObject *res = PyObject_CallFunction(data->plugin_cleanup_func, NULL);
        if (res == NULL) {
            fprintf(stderr, "pyauth plugin_cleanup failed\n");
            PyErr_Print();
        }
        Py_DECREF(res);
    }

    Py_DECREF(data->module);
    Py_XDECREF(data->plugin_cleanup_func);
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

int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password)
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
