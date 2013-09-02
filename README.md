mosquitto_pyauth
================

Mosquitto auth plugin that lets you write your auth plugins in Python.

Compiling
=========

Make sure you have Python dev package installed (`apt-get install
python-dev` under Debian/Ubuntu).

Download mosquitto sources and clone this repository at the top of the
mosquitto source directory. Then:

    cd mosquitto_pyauth
    make

If all goes ok, there should be `auth_plugin_pyauth.so` file in the
current directory. Copy it under path accessible for mosquitto daemon,
e.g.: `/usr/local/lib/mosquitto/`.

Running
=======

Add following line to `mosquitto.conf`:

    auth_plugin /path/to/auth_plugin_pyauth.so

You must also give a pointer to Python module which is going to be
loaded (make sure it's in Python path, use `PYTHONPATH` env variable
to the rescue):

    auth_opt_pyauth_module some_module

Python module
=============

Python module should do required initializations when it's imported
and provide following global functions:

* `unpwd_check_func(username, password)`: return `True` if given
  username and password pair is allowed to log in
