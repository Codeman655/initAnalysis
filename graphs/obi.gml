<?xml version='1.0' encoding='utf-8'?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">
  <graph edgedefault="undirected">
    <node id="rcS" />
    <node id="/bin/sh" />
    <node id="/etc/rc" />
    <node id="hostapd" />
    <node id="/WPA/WPA2/EAP" />
    <node id="/usr/bin/hostapd" />
    <node id="/var/tmp/hostapd" />
    <node id="/var/run/hostapd" />
    <node id="/usr/etc/init-functions" />
    <node id="/dev/null" />
    <node id="/etc/init" />
    <node id="dbus" />
    <node id="/usr/bin/dbus-send" />
    <node id="/usr/bin/dbus-daemon" />
    <node id="/usr/bin/dbus-uuidgen" />
    <node id="/var/run/dbus" />
    <node id="/pid" />
    <node id="/bluetooth" />
    <node id="/proc" />
    <node id="/exe" />
    <node id="/usr/bin/start-stop-daemon" />
    <node id="bluetooth" />
    <node id="/usr/sbin/bluetoothd" />
    <node id="/usr/sbin/hciattach" />
    <node id="/usr/sbin/rfcomm" />
    <node id="/usr/etc/bluetooth/rfcomm" />
    <node id="/usr/sbin/sdptool" />
    <node id="inittab" />
    <node id="init" />
    <node id="init-functions" />
    <node id="init.lua" />
    <node id="init.tcl" />
    <edge source="rcS" target="/bin/sh" />
    <edge source="rcS" target="/etc/rc" />
    <edge source="/bin/sh" target="hostapd" />
    <edge source="/bin/sh" target="dbus" />
    <edge source="/bin/sh" target="bluetooth" />
    <edge source="hostapd" target="/WPA/WPA2/EAP" />
    <edge source="hostapd" target="/usr/bin/hostapd" />
    <edge source="hostapd" target="/var/tmp/hostapd" />
    <edge source="hostapd" target="/var/run/hostapd" />
    <edge source="hostapd" target="/usr/etc/init-functions" />
    <edge source="hostapd" target="/dev/null" />
    <edge source="hostapd" target="/etc/init" />
    <edge source="/usr/etc/init-functions" target="dbus" />
    <edge source="/usr/etc/init-functions" target="bluetooth" />
    <edge source="/dev/null" target="dbus" />
    <edge source="/dev/null" target="bluetooth" />
    <edge source="/etc/init" target="dbus" />
    <edge source="dbus" target="/usr/bin/dbus-send" />
    <edge source="dbus" target="/usr/bin/dbus-daemon" />
    <edge source="dbus" target="/usr/bin/dbus-uuidgen" />
    <edge source="dbus" target="/var/run/dbus" />
    <edge source="dbus" target="/pid" />
    <edge source="dbus" target="/bluetooth" />
    <edge source="dbus" target="/proc" />
    <edge source="dbus" target="/exe" />
    <edge source="dbus" target="/usr/bin/start-stop-daemon" />
    <edge source="/usr/bin/start-stop-daemon" target="bluetooth" />
    <edge source="bluetooth" target="/usr/sbin/bluetoothd" />
    <edge source="bluetooth" target="/usr/sbin/hciattach" />
    <edge source="bluetooth" target="/usr/sbin/rfcomm" />
    <edge source="bluetooth" target="/usr/etc/bluetooth/rfcomm" />
    <edge source="bluetooth" target="/usr/sbin/sdptool" />
  </graph>
</graphml>
