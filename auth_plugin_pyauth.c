#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <Python.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>

#if !defined(LIBMOSQUITTO_VERSION_NUMBER) || LIBMOSQUITTO_VERSION_NUMBER < 1002001
#error "mosquitto 1.2.1 or higher is required"
#endif

struct pyauth_data {
    char *module_name;
    PyObject *module;
    PyObject *plugin_cleanup_func;
    PyObject *unpwd_check_func;
    PyObject *acl_check_func;
    PyObject *security_init_func;
    PyObject *security_cleanup_func;
    PyObject *psk_key_get_func;
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
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

/* Aux "mosquitto_auth" module */

static PyObject *pyauth_mosquitto_topic_matches_sub(PyObject *self unused, PyObject *args)
{
    const char *sub;
    const char *topic;

    if (!PyArg_ParseTuple(args, "ss", &sub, &topic))
        return NULL;

    bool res;
    mosquitto_topic_matches_sub(sub, topic, &res);

    return PyBool_FromLong(res);
}

static PyObject *pyauth_mosquitto_log_printf(PyObject *self unused, PyObject *args)
{
    int loglevel;
    char *fmt;

    if (!PyArg_ParseTuple(args, "is", &loglevel, &fmt))
    return NULL;

    mosquitto_log_printf(loglevel, "%s", fmt);

    Py_RETURN_NONE;
}


static PyMethodDef methods[] = {
    {"topic_matches_sub", pyauth_mosquitto_topic_matches_sub, METH_VARARGS,
     "Check whether a topic matches a subscription"},
     {"log", pyauth_mosquitto_log_printf, METH_VARARGS,
     "Log a message into mosquitto's log"},
    {NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {
        .m_base = PyModuleDef_HEAD_INIT,
        .m_name = "mosquitto_auth",
        .m_methods = methods
};
#endif

static PyObject *init_aux_module(void)
{
#if PY_MAJOR_VERSION >= 3
    PyObject *module = PyModule_Create(&moduledef);
#else
    PyObject *module = Py_InitModule("mosquitto_auth", methods);
#endif
    if (module == NULL)
        return NULL;

    PyModule_AddIntConstant(module, "MOSQ_ACL_NONE", MOSQ_ACL_NONE);
    PyModule_AddIntConstant(module, "MOSQ_ACL_READ", MOSQ_ACL_READ);
    PyModule_AddIntConstant(module, "MOSQ_ACL_WRITE", MOSQ_ACL_WRITE);

    /* loglevel */
    PyModule_AddIntConstant(module, "LOG_INFO", MOSQ_LOG_INFO);
    PyModule_AddIntConstant(module, "LOG_NOTICE", MOSQ_LOG_NOTICE);
    PyModule_AddIntConstant(module, "LOG_WARNING", MOSQ_LOG_WARNING);
    PyModule_AddIntConstant(module, "LOG_ERR", MOSQ_LOG_ERR);
    PyModule_AddIntConstant(module, "LOG_DEBUG", MOSQ_LOG_DEBUG);
    PyModule_AddIntConstant(module, "LOG_SUBSCRIBE", MOSQ_LOG_SUBSCRIBE);
    PyModule_AddIntConstant(module, "LOG_UNSUBSCRIBE", MOSQ_LOG_UNSUBSCRIBE);

    return module;
}


/* Plugin entry points */

int mosquitto_auth_plugin_version(void)
{
    return MOSQ_AUTH_PLUGIN_VERSION;
}

static PyObject *make_auth_opts_tuple(struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
    PyObject *optlist = PyTuple_New(auth_opt_count - 1); /* -1 because of skipped "pyauth_module" */
    if (optlist == NULL)
        return NULL;

    int idx = 0;
    for (int i = 0; i < auth_opt_count; i++) {
        if (!strcmp(auth_opts[i].key, "pyauth_module"))
            continue;

        PyObject *elt = PyTuple_Pack(2,
                                     PyUnicode_FromString(auth_opts[i].key),
                                     PyUnicode_FromString(auth_opts[i].value));
        if (elt == NULL) {
            Py_DECREF(optlist);
            return NULL;
        }

        PyTuple_SET_ITEM(optlist, idx++, elt);
    }

    return optlist;
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

#if PY_MAJOR_VERSION >= 3
    PyImport_AppendInittab("mosquitto_auth", &init_aux_module);
#endif

    Py_Initialize();
#if PY_MAJOR_VERSION < 3
    if (init_aux_module() == NULL)
        die(false, "failed to initialize auxiliary module");
#endif

    data->module = PyImport_ImportModule(data->module_name);
    if (data->module == NULL)
        die(true, "failed to import module: %s", data->module_name);

    data->plugin_cleanup_func = PyObject_GetAttrString(data->module, "plugin_cleanup");
    data->unpwd_check_func = PyObject_GetAttrString(data->module, "unpwd_check");
    data->acl_check_func = PyObject_GetAttrString(data->module, "acl_check");
    data->security_init_func = PyObject_GetAttrString(data->module, "security_init");
    data->security_cleanup_func = PyObject_GetAttrString(data->module, "security_cleanup");
    data->psk_key_get_func = PyObject_GetAttrString(data->module, "psk_key_get");
    PyErr_Clear();  /* don't care about AttributeError from above code */

    PyObject *init_func = PyObject_GetAttrString(data->module, "plugin_init");
    if (init_func != NULL) {
        PyObject *optlist = make_auth_opts_tuple(auth_opts, auth_opt_count);
        if (optlist == NULL)
            die(true, "python module initialization failed");

        PyObject *res = PyObject_CallFunctionObjArgs(init_func, optlist, NULL);
        if (res == NULL)
            die(true, "python module initialization failed");
        Py_DECREF(res);

        Py_DECREF(optlist);
        Py_DECREF(init_func);
    }
    PyErr_Clear();

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
        Py_XDECREF(res);
    }

    Py_DECREF(data->module);
    Py_XDECREF(data->plugin_cleanup_func);
    Py_XDECREF(data->unpwd_check_func);
    Py_XDECREF(data->acl_check_func);
    Py_XDECREF(data->security_init_func);
    Py_XDECREF(data->security_cleanup_func);
    Py_XDECREF(data->psk_key_get_func);
    free(data->module_name);
    free(data);
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
    struct pyauth_data *data = user_data;

    if (data->security_init_func == NULL)
        return MOSQ_ERR_SUCCESS;

    PyObject *optlist = make_auth_opts_tuple(auth_opts, auth_opt_count);
    if (optlist == NULL)
        goto err_no_optlist;

    PyObject *py_reload = PyBool_FromLong(reload);

    PyObject *res = PyObject_CallFunctionObjArgs(data->security_init_func, optlist, py_reload, NULL);
    if (res == NULL)
        goto err_call_failed;
    Py_DECREF(res);

    Py_DECREF(py_reload);
    Py_DECREF(optlist);

    return MOSQ_ERR_SUCCESS;

err_call_failed:
    Py_XDECREF(py_reload);
    Py_XDECREF(optlist);
err_no_optlist:
    fprintf(stderr, "pyauth security_init failed\n");
    PyErr_Print();
    return MOSQ_ERR_UNKNOWN;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts unused, int auth_opt_count unused, bool reload)
{
    struct pyauth_data *data = user_data;

    if (data->security_cleanup_func == NULL)
        return MOSQ_ERR_SUCCESS;

    PyObject *py_reload = PyBool_FromLong(reload);

    PyObject *res = PyObject_CallFunctionObjArgs(data->security_cleanup_func, py_reload, NULL);
    Py_DECREF(py_reload);
    if (res == NULL) {
        fprintf(stderr, "pyauth security_cleanup failed\n");
        PyErr_Print();
        return MOSQ_ERR_UNKNOWN;
    }
    Py_DECREF(res);

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access)
{
    struct pyauth_data *data = user_data;

    if (data->acl_check_func == NULL)
        return MOSQ_ERR_ACL_DENIED;

    PyObject *res = PyObject_CallFunction(data->acl_check_func, "sssi", clientid, username, topic, access);
    if (res == NULL) {
        PyErr_Print();
        return MOSQ_ERR_UNKNOWN;
    }
    int ok = PyObject_IsTrue(res);
    Py_DECREF(res);

    return ok ? MOSQ_ERR_SUCCESS : MOSQ_ERR_ACL_DENIED;
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

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len)
{
    struct pyauth_data *data = user_data;
    char psk[max_key_len];

    if (identity == NULL)
        return MOSQ_ERR_AUTH;

    debug("mosquitto_auth_psk_key_get: identity=%s, hint=%s", identity, hint);

    if (data->psk_key_get_func == NULL)
        return MOSQ_ERR_AUTH;

    PyObject *res = PyObject_CallFunction(data->psk_key_get_func, "ss", identity, hint);
    if (res == NULL) {
        PyErr_Print();
        return MOSQ_ERR_UNKNOWN;
    }

    if (res == Py_None || !PyObject_IsTrue(res)) {
        goto error;
    }

    if (!PyBytes_Check(res)) {
        PyObject *res2 = PyUnicode_AsASCIIString(res);
        if (res2 == NULL)
            goto error;
        Py_DECREF(res);
        res = res2;
    }

    int len = snprintf(psk, sizeof(psk), "%s", PyBytes_AsString(res));
    if (len < 0) {
        fprintf(stderr, "mosquitto_auth_psk_key_get: copy psk failed\n");
        goto error;
    }

    if (len > max_key_len) {
        fprintf(stderr, "mosquitto_auth_psk_key_get: psk length [%d] > max_key_len [%d]\n", len, max_key_len);
        goto error;
    }

    debug("mosquitto_auth_psk_key_get: psk=%s", psk);
    strncpy(key, psk, max_key_len);
    Py_DECREF(res);

    return MOSQ_ERR_SUCCESS;

error:
    Py_DECREF(res);
    return MOSQ_ERR_AUTH;
}
