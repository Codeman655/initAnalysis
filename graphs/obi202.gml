<?xml version='1.0' encoding='utf-8'?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">
  <graph edgedefault="undirected">
    <node id="rcS" />
    <node id="/bin" />
    <node id="/sh" />
    <node id="/etc" />
    <node id="/rc" />
    <node id="hostapd" />
    <node id="/WPA" />
    <node id="/WPA2" />
    <node id="/EAP" />
    <node id="/usr" />
    <node id="/hostapd" />
    <node id="/var" />
    <node id="/tmp" />
    <node id="/run" />
    <node id="/init-functions" />
    <node id="/dev" />
    <node id="/null" />
    <node id="/init" />
    <node id="dbus" />
    <node id="/dbus-send" />
    <node id="/dbus-daemon" />
    <node id="/dbus-uuidgen" />
    <node id="/dbus" />
    <node id="/pid" />
    <node id="/bluetooth" />
    <node id="/proc" />
    <node id="/exe" />
    <node id="/start-stop-daemon" />
    <node id="bluetooth" />
    <node id="/sbin" />
    <node id="/bluetoothd" />
    <node id="/hciattach" />
    <node id="/rfcomm" />
    <node id="/sdptool" />
    <node id="inittab" />
    <node id="init" />
    <node id="init-functions" />
    <node id="init.lua" />
    <node id="init.tcl" />
    <edge source="rcS" target="/bin" />
    <edge source="rcS" target="/sh" />
    <edge source="rcS" target="/etc" />
    <edge source="rcS" target="/rc" />
    <edge source="/bin" target="hostapd" />
    <edge source="/bin" target="dbus" />
    <edge source="/bin" target="bluetooth" />
    <edge source="/sh" target="hostapd" />
    <edge source="/sh" target="dbus" />
    <edge source="/sh" target="bluetooth" />
    <edge source="/etc" target="hostapd" />
    <edge source="/etc" target="dbus" />
    <edge source="/etc" target="bluetooth" />
    <edge source="hostapd" target="/WPA" />
    <edge source="hostapd" target="/WPA2" />
    <edge source="hostapd" target="/EAP" />
    <edge source="hostapd" target="/usr" />
    <edge source="hostapd" target="/hostapd" />
    <edge source="hostapd" target="/var" />
    <edge source="hostapd" target="/tmp" />
    <edge source="hostapd" target="/run" />
    <edge source="hostapd" target="/init-functions" />
    <edge source="hostapd" target="/dev" />
    <edge source="hostapd" target="/null" />
    <edge source="hostapd" target="/init" />
    <edge source="/usr" target="dbus" />
    <edge source="/usr" target="bluetooth" />
    <edge source="/var" target="dbus" />
    <edge source="/run" target="dbus" />
    <edge source="/init-functions" target="dbus" />
    <edge source="/init-functions" target="bluetooth" />
    <edge source="/dev" target="dbus" />
    <edge source="/dev" target="bluetooth" />
    <edge source="/null" target="dbus" />
    <edge source="/null" target="bluetooth" />
    <edge source="/init" target="dbus" />
    <edge source="dbus" target="/dbus-send" />
    <edge source="dbus" target="/dbus-daemon" />
    <edge source="dbus" target="/dbus-uuidgen" />
    <edge source="dbus" target="/dbus" />
    <edge source="dbus" target="/pid" />
    <edge source="dbus" target="/bluetooth" />
    <edge source="dbus" target="/proc" />
    <edge source="dbus" target="/exe" />
    <edge source="dbus" target="/start-stop-daemon" />
    <edge source="/bluetooth" target="bluetooth" />
    <edge source="/start-stop-daemon" target="bluetooth" />
    <edge source="bluetooth" target="/sbin" />
    <edge source="bluetooth" target="/bluetoothd" />
    <edge source="bluetooth" target="/hciattach" />
    <edge source="bluetooth" target="/rfcomm" />
    <edge source="bluetooth" target="/sdptool" />
  </graph>
</graphml>
