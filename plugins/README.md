# Firebytes Plugin README 

## Summary

This README is here to give you a basic understanding on how to build some plugins. There is currently 1 plugin (hello.fireplug) included and 2 examples, these are:

* &lt;repo_base&gt;/plugins/examples/dummy.plug
* &lt;repo_base&gt;/plugins/examples/metasploit.plug

Take a look at "dummy.plug" for a basic idea on how plugins must be setup. If you want to use the [Metasploit Framework](https://www.metasploit.com/), it's recommended that you take a look at metasploit.plug

## Building Plugins

Plugins are simply Python scripts with a bit of special structure who are GZipped. That's it, nothing fancy. So writing a plugin should be very straight-foreward: simply write it like you would any other python script/module. There is a special module that you have access to when running as a FirePlug: fireIO logging. This is simply a class that does some fancy logging for you via the Firebytes application. See "FireIO Logger" down below for more.

Let's run through a basic script:
```python
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
```

Here we see the basic setup of a plugin. Every plugin MUST have the following:
* \# FIREPLUG_NAME: &lt;name of plugin&gt;
* \# FIREPLUG_UID: &lt;unique description of plugin in 1 line&gt;
* Init() definition
* Run() definition
* Destroy() definition

The 3 definitions [Init(), Run(), and Destroy()] must allow these two arguments to be passed to them by Firebytes: a Pything list of arguments, and an integer. The arguments, as of right now, have a structure of:
[0] -&gt; hostname to test
[1..] -&gt; N/A

This is due to Firebytes still being in it's infancy.
The plug_id (integer) is simply the UUID of the plugin when loaded by Firebytes. This can be used for self-checking and logging.

Once you have your plugin written, save it as a "\*.py" file in the following directory: "&lt;repo_base&gt;/utils/plugins". Then run the "mkplugins" script in the "&lt;repo_base&gt;/utils" directory.
**NOTE:** When you run "mkplugins", you need to be *in* the "utils" directory.

## FireIO Logger

As mentioned earlier, there is a special logging utility that is available to the plugins: fireIO. This utility to simply added when you add the following import:
```python
from sec_utils.logger import fireIO
```

This exposes the `fireIO` object to you so that you can log to the Firebytes logging system from within your plugin. This object will expose the following API calls to you:
```python
fireIO.write(line, level="Info", debug_info="", plugin_id=0) # Write out a line.
fireIO.set_debug(enabled=True) # Toggle debugging messages.
fireIO.DumpLog() # Dump log to disk.
fireIO.TruncateLog() # Truncate the log to 0 bytes.
```

`line` is the actual message you want to print to the logging system.

`fireIO.write` takes the following for "level" (case-insensitive):
* Fatal (Error)
* Critical | Error
* Warn(ing)
* Info(rmation)
* Debug | Trace
* Failure
* Success
* Plugin

They look like the following in your shell:
![https://i.imgur.com/hJPZDnq.png](https://i.imgur.com/hJPZDnq.png "Log Levels in Shell")

The `debug_info` argument is optional and allows you to pass potential debugging information at any level, this allows you to "trace" log statements and the call stack to a degree.

The `plugin_id` argument is only used when the level is "Plugin" and it specifies the digit that follows "Plugin" on the log line. This can be a string or digit.

# Metasploit

## What is it?

The [Metasploit Framework](https://www.metasploit.com/) is a collection of exploits found by hackers and SecOps engineers that hobbists use to pen-test their own things. The plugin system has been designed in such a way that [Metasploit](https://www.metasploit.com/) works "out-of-the-box" so to say.
Using these plugins does however, require that you have Metasploit installed: https://metasploit.help.rapid7.com/docs/installing-the-metasploit-framework

## Metasploit Plugins

Since writing a plugin can be a pain for non-Python devs, there is an example plugin that is provided for metasploit. This plugin actually works off of a "Metasploit Resource" document. 
That document is actually a list of commands for the msfconsole that are run in a procedural (top-to-bottom) manner. The plugin will first attempt to pull down the resource doc. if it doesn't exist,
it will then attempt to run the "msfconsole" command, using the resource document and parsing the commands output into a format that Firebytes understands. The plugin then will finish by returning the data to Firebytes
as a Python list full of tuples. This enables Firebytes to know who suceeded/failed so it can report accordingly.

The best way to go about making a metasploit plugin is to copy the existing example, and tweak it to use your custom resource files so that way it tests what you're after.