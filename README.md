# Spy Connect
This is a new plugin for SecuritySpy integration with Indigo.  It is not based on any previous plugin, but is a complete rewrite.  

It is designed to work with Indigo 2024.0.0 or later and SecuritySpy 6 or later.

## Features
- Provide Indigo event triggers for motion type events in SecuritySpy.
- Provide visibility into SecuritySpy camera status in Indigo Devices.

## Installation

Install plugin as per usual.  Once installed, you will first need to create a "Security Spy Server" device.  This device
will contain the IP address of the SecuritySpy server, and the port number that SecuritySpy is listening on.  The plugin uses 
Zeroconf to find available SecuritySpy servers on your network, so you can select the server from a list.  
Manual entry of IP address and port is also supported.

You will need to provide the username and password for the SecuritySpy server.  This is the username and password that you 
use to log into the SecuritySpy web interface.

## Usage

Once the SecuritySpy Server device is created, you can create a "SecuritySpy Camera" device for each camera that you want to monitor.

You can create event triggers for any motion event, for a specific camera, or for any camera.  The event trigger will fire when the
SecuritySpy server reports a motion event for the camera(s).  Note that SS generates a LOT of motion events, so creating generic
motion triggers is not recommended.

You can also create triggers for object detection events.  There are events for "person", "vehicle", and "animal". See the SecuritySpy
documentation for more information on object detection.

## Limitations

At this time the plugin does not provide any control of the cameras or Security Spy in general.  That will be added in a future release.

