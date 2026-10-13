#!/usr/bin/env python3
"""A small Secret Service (org.freedesktop.secrets) for tests, on whatever
session bus it is started on. One "default" collection that starts locked:
unlocking goes through a prompt that completes at once, like a keyring whose
password dialog the user confirms. Each run writes its state to the file given
as the first argument, so a test can check what was stored.
"""
import json
import sys

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

SERVICE = "org.freedesktop.secrets"
PREFIX = "/org/freedesktop/secrets"
STATE = sys.argv[1]


class State:
    locked = True
    prompts = 0
    items = {}      # path -> {"attributes": {}, "label": str, "secret": bytes}
    next_id = 0
    open_sessions = 0


def save():
    with open(STATE, "w") as f:
        json.dump({"locked": State.locked, "prompts": State.prompts, "open_sessions": State.open_sessions,
                   "items": [{"label": i["label"], "attributes": i["attributes"], "secret": i["secret"].decode()}
                             for i in State.items.values()]}, f)


class Prompt(dbus.service.Object):
    def __init__(self, bus, path, action):
        super().__init__(bus, path)
        self.action = action

    @dbus.service.method("org.freedesktop.Secret.Prompt", in_signature="s")
    def Prompt(self, window_id):
        State.prompts += 1
        self.action()
        save()
        GLib.idle_add(lambda: self.Completed(False, dbus.String("", variant_level=1)) and False)

    @dbus.service.method("org.freedesktop.Secret.Prompt")
    def Dismiss(self):
        self.Completed(True, dbus.String("", variant_level=1))

    @dbus.service.signal("org.freedesktop.Secret.Prompt", signature="bv")
    def Completed(self, dismissed, result):
        pass


class Session(dbus.service.Object):
    @dbus.service.method("org.freedesktop.Secret.Session")
    def Close(self):
        State.open_sessions -= 1
        save()
        GLib.idle_add(lambda: self.remove_from_connection() and False)


class Item(dbus.service.Object):
    def __init__(self, bus, path):
        super().__init__(bus, path)
        self.path = path

    @dbus.service.method("org.freedesktop.Secret.Item", in_signature="o", out_signature="(oayays)")
    def GetSecret(self, session):
        if State.locked:
            raise dbus.exceptions.DBusException("locked", name="org.freedesktop.Secret.Error.IsLocked")
        secret = State.items[self.path]["secret"]
        return (session, dbus.ByteArray(b""), dbus.ByteArray(secret), "text/plain")

    @dbus.service.method("org.freedesktop.Secret.Item", out_signature="o")
    def Delete(self):
        State.items.pop(self.path, None)
        GLib.idle_add(lambda: self.remove_from_connection() and False)   # after the reply is sent
        save()
        return dbus.ObjectPath("/")


class Collection(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, PREFIX + "/collection/login")
        self.bus = bus

    @dbus.service.method("org.freedesktop.Secret.Collection", in_signature="a{sv}(oayays)b", out_signature="oo")
    def CreateItem(self, properties, secret, replace):
        if State.locked:
            raise dbus.exceptions.DBusException("locked", name="org.freedesktop.Secret.Error.IsLocked")
        attributes = {str(k): str(v) for k, v in properties.get("org.freedesktop.Secret.Item.Attributes", {}).items()}
        if replace:
            for path, item in list(State.items.items()):
                if item["attributes"] == attributes:
                    item["secret"] = bytes(secret[2])
                    save()
                    return (dbus.ObjectPath(path), dbus.ObjectPath("/"))
        State.next_id += 1
        path = f"{PREFIX}/collection/login/{State.next_id}"
        State.items[path] = {"attributes": attributes, "label": str(properties.get("org.freedesktop.Secret.Item.Label", "")),
                             "secret": bytes(secret[2])}
        Item(self.bus, path)
        save()
        return (dbus.ObjectPath(path), dbus.ObjectPath("/"))


class Service(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, PREFIX)
        self.bus = bus
        self.collection = Collection(bus)
        self.prompt_id = 0
        self.session_id = 0

    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="sv", out_signature="vo")
    def OpenSession(self, algorithm, value):
        if algorithm != "plain":
            raise dbus.exceptions.DBusException("unsupported", name="org.freedesktop.DBus.Error.NotSupported")
        self.session_id += 1
        path = f"{PREFIX}/session/{self.session_id}"
        Session(self.bus, path)
        State.open_sessions += 1
        save()
        return (dbus.String("", variant_level=1), dbus.ObjectPath(path))

    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="s", out_signature="o")
    def ReadAlias(self, name):
        return dbus.ObjectPath(PREFIX + "/collection/login" if name == "default" else "/")

    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="a{ss}", out_signature="aoao")
    def SearchItems(self, attributes):
        wanted = {str(k): str(v) for k, v in attributes.items()}
        found = [dbus.ObjectPath(p) for p, i in State.items.items() if all(i["attributes"].get(k) == v for k, v in wanted.items())]
        empty = dbus.Array([], signature="o")
        return (empty, dbus.Array(found, signature="o")) if State.locked else (dbus.Array(found, signature="o"), empty)

    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="ao", out_signature="aoo")
    def Unlock(self, objects):
        if not State.locked:
            return (objects, dbus.ObjectPath("/"))
        self.prompt_id += 1
        path = f"{PREFIX}/prompt/{self.prompt_id}"

        def unlock():
            State.locked = False
        Prompt(self.bus, path, unlock)
        return (dbus.Array([], signature="o"), dbus.ObjectPath(path))


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    Service(bus)
    save()
    name = dbus.service.BusName(SERVICE, bus)  # owned while referenced
    GLib.MainLoop().run()
    del name


if __name__ == "__main__":
    main()
