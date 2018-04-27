#!/usr/bin/env python
# *-* coding: utf-8 *-*

# FIREPLUG_NAME: Hello
# FIREPLUG_UID: Hello World
# FIREPLUG_VER: 1

from sec_utils.logger import fireIO

g_msg = None

def Init(args=[], plug_id=0):
    global g_msg

    g_msg = "Hello World"

    return True

def Run(args=[], plug_id=0):
    global g_msg

    fireIO.write(g_msg, "Plugin", plugin_id=plug_id)

    return [(True, 'Hello')]

def Destroy(args=[], plug_id=0):
    global g_msg

    g_msg = None