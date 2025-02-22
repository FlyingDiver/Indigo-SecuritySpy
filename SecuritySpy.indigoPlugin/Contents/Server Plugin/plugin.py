#! /usr/bin/env python
# -*- coding: utf-8 -*-
from aiohttp import ClientSession
import asyncio
import logging
import json
import os
from base64 import b64encode
import time
import threading
import queue
import requests
from pysecspy.secspy_server import SecSpyServer

from zeroconf import IPVersion, ServiceBrowser, ServiceStateChange, Zeroconf

class Plugin(indigo.PluginBase):

    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)

        pfmt = logging.Formatter('%(asctime)s.%(msecs)03d\t[%(levelname)8s] %(name)20s.%(funcName)-25s%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        self.plugin_file_handler.setFormatter(pfmt)
        self.log_level = int(pluginPrefs.get("logLevel", logging.DEBUG))
        self.logger.debug(f"log_level = {self.log_level}")
        self.indigo_log_handler.setLevel(self.log_level)
        self.plugin_file_handler.setLevel(self.log_level)

        self.pluginId = pluginId
        self.pluginPrefs = pluginPrefs
        self.triggers = []
        self.event_loop = None
        self.async_thread = None

        self.found_servers = {}     # zeroconf discovered SecuritySpy servers
        self.spy_servers = {}       # SecuritySpy server objects by Indigo device id
        self.spy_devices = {}       # indigo device IDs for SecuritySpy servers by server_id
        self.spy_cameras = {}       # indigo devices for SecuritySpy cameras by camera address
        self.camera_info = {}       # Current Camera Information

        self.client_session = None

        self.update_frequency = float(self.pluginPrefs.get('update_frequency', "1")) * 60.0
        self.next_update = time.time()

    ##############################################################################################

    def startup(self):
        self.logger.debug("startup")
        threading.Thread(target=self.run_async_thread).start()
        self.sleep(2)
        ServiceBrowser(Zeroconf(ip_version=IPVersion.V4Only), ["_securityspy._tcp.local."], handlers=[self.on_service_state_change])
        self.logger.debug("startup complete")

    def run_async_thread(self):
        self.logger.debug("run_async_thread starting")
        self.event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.event_loop)
        self.event_loop.run_until_complete(self.async_main())
        self.event_loop.close()
        self.logger.debug("run_async_thread exiting")

    async def async_main(self):
        self.logger.debug("async_main starting")
        self.client_session = ClientSession()
        while True:
            await asyncio.sleep(0.1)
            if time.time() > self.next_update:
                self.next_update = time.time() + self.update_frequency
                for device_id in self.spy_servers.keys():
                    await self.update_spy_server(indigo.devices[device_id])
            if self.stopThread:
                self.logger.debug("async_main: stopping")
                break
        self.logger.debug("async_main exiting")

    def on_service_state_change(self, zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange) -> None:
        self.logger.threaddebug(f"Service {name} of type {service_type} state changed: {state_change}: {zeroconf.get_service_info(service_type, name)}")

        if state_change in [ServiceStateChange.Added, ServiceStateChange.Updated]:
            info = zeroconf.get_service_info(service_type, name)
            ipaddr = ".".join([f"{x}" for x in info.addresses[0]])  # ip address as string (xx.xx.xx.xx)
            port = int(info.properties[b'portp'])
            address = f"{ipaddr}:{port}"
            if address not in self.found_servers:
                self.found_servers[address] = f"{info.server}"
                self.logger.debug(f"Adding Found Server: {address} == {info}")

        elif state_change is ServiceStateChange.Removed:
            info = zeroconf.get_service_info(service_type, name)
            ipaddr = ".".join([f"{x}" for x in info.addresses[0]])  # address as string (xx.xx.xx.xx)
            if ipaddr in self.found_servers:
                del self.found_servers[ipaddr]

    def closed_prefs_config_ui(self, valuesDict, userCancelled):
        self.logger.threaddebug(f"closed_prefs_config_ui, valuesDict = {valuesDict}")
        if not userCancelled:
            self.log_level = int(valuesDict.get("log_level", logging.INFO))
            self.logger.debug(f"log_level = {self.log_level}")
            self.indigo_log_handler.setLevel(self.log_level)
            self.plugin_file_handler.setLevel(self.log_level)

            self.update_frequency = float(self.pluginPrefs.get('update_frequency', "1")) * 60.0
            self.logger.debug(f"update_frequency = {self.update_frequency}")
            self.next_update = time.time() + self.update_frequency

    ##############################################################################################
    # Event Handlers
    ##############################################################################################

    def camera_event(self, event_info):
        self.logger.threaddebug(f"camera_event: event_info = {json.dumps(event_info, sort_keys=True, indent=4)}")

        for camera_num, camera_data in event_info.items():
            camera_address = f"{camera_data['server_id']}:{int(camera_num):02d}"
            self.camera_info[camera_address] = camera_data
            self.update_camera_device(camera_address, camera_data)

            self.logger.threaddebug(f"camera_event: camera = {camera_address}, event_type = {camera_data['event_type']}, event_object = {camera_data['event_object']}")

            # only process motion events
            if camera_data['event_type'] != "motion":
                self.logger.debug(f"camera_event: skipping event {camera_data['event_type']} for {camera_address}")
                continue

            for triggerID in self.triggers:
                trigger = indigo.triggers[triggerID]

                if not ((trigger.pluginProps["camera"] == "-1") or (trigger.pluginProps["camera"] == camera_address)):
                    continue

                if trigger.pluginTypeId == "motion_event":
                    self.logger.debug(f"motion_event for {camera_address}")
                    indigo.trigger.execute(trigger)

                elif trigger.pluginTypeId == "person_event" and camera_data['event_object'] == "Human":
                    self.logger.debug(f"person_event for {camera_address}")
                    indigo.trigger.execute(trigger)

                elif trigger.pluginTypeId == "vehicle_event" and camera_data['event_object'] == "Vehicle":
                    self.logger.debug(f"vehicle_event for {camera_address}")
                    indigo.trigger.execute(trigger)

                elif trigger.pluginTypeId == "animal_event" and camera_data['event_object'] == "Animal":
                    self.logger.debug(f"animal_event for {camera_address}")
                    indigo.trigger.execute(trigger)

    ##################
    # Device Methods
    ##################

    def validate_device_config_ui(self, valuesDict, typeId, devId):
        self.logger.debug(f"validateDeviceConfigUi, typeId = {typeId}, devId = {devId}, valuesDict = {valuesDict}")
        return True, valuesDict

    def device_start_comm(self, device):
        self.logger.debug(f"{device.name}: Starting Device")

        if device.deviceTypeId == 'spyServer':
            self.spy_servers[device.id] = SecSpyServer(self.client_session,
                                  device.pluginProps['ip_address'],
                                  device.pluginProps['port'],
                                  device.pluginProps['username'],
                                  device.pluginProps['password'])
            self.event_loop.create_task(self.spy_connect(device))

        elif device.deviceTypeId == 'spyCamera':
            self.spy_cameras[device.address] = device.id
            if camera_info := self.camera_info.get(device.address):
                self.update_camera_device(device.address, camera_info)

    def device_stop_comm(self, device):
        self.logger.debug(f"{device.name}: Stopping Device")

        if device.deviceTypeId == 'spyServer':
            self.event_loop.create_task(self.spy_connect(device))

        elif device.deviceTypeId == 'spyCamera':
            del self.spy_cameras[device.address]

    async def spy_connect(self, device):
        self.logger.debug(f"{device.name}: Connecting to Spy Server")
        self.spy_servers[device.id].subscribe_websocket(self.camera_event)
        info = await self.spy_servers[device.id].get_server_information()
        self.logger.debug(f"{device.name}: Server: {json.dumps(info, sort_keys=True, indent=4)}")
        self.spy_devices[info['server_id']] = device.id
        update_list = [
            {'key': "server_id", 'value': info['server_id']},
            {'key': "server_name", 'value': info['server_name']},
            {'key': "server_version", 'value': info['server_version']},
        ]
        try:
            device.updateStatesOnServer(update_list)
        except Exception as e:
            self.logger.error(f"{device.name}: failed to update states: {e}")

        await asyncio.sleep(5.0)    # wait for camera devices to be started before updating them
        await self.update_spy_server(device)

    async def spy_disconnect(self, device):
        self.logger.debug(f"{device.name}: Disconnecting from Spy Server")
        await self.spy_servers[device.id].async_disconnect_ws()
        del self.spy_servers[device.id]

    async def update_spy_server(self, device):
        self.logger.threaddebug(f"{device.name}: Updating Server")
        data = await self.spy_servers[device.id].update()
        for camera_num, camera_data in data.items():
            camera_address = f"{camera_data['server_id']}:{int(camera_num):02d}"
            self.camera_info[camera_address] = camera_data
            self.update_camera_device(camera_address, camera_data)

    def update_camera_device(self, camera_address, camera_info):
        device_id = self.spy_cameras.get(camera_address)
        device = indigo.devices.get(device_id)
        if not device:
            return

        self.logger.threaddebug(f"{device.name}: Updating Camera Information")
        update_list = [{'key': k, 'value': camera_info[k]} for k in camera_info.keys() if k not in ['ptz_presets']]
        self.logger.threaddebug(f"{device.name}: Update List: {update_list}")
        try:
            device.updateStatesOnServer(update_list)
        except Exception as e:
            self.logger.error(f"{device.name}: failed to update states: {e}")

    ########################################
    # Trigger (Event) handling
    ########################################

    def trigger_start_processing(self, trigger):
        self.logger.debug(f"{trigger.name}: Adding Trigger")
        assert trigger.id not in self.triggers
        self.triggers.append(trigger.id)

    def trigger_stop_processing(self, trigger):
        self.logger.debug(f"{trigger.name}: Removing Trigger")
        assert trigger.id in self.triggers
        self.triggers.remove(trigger.id)

    ########################################
    # callbacks from device creation UI
    ########################################

    def get_server_list(self, filter="", valuesDict=None, typeId="", targetId=0):
        self.logger.threaddebug(f"get_found_servers: typeId = {typeId}, targetId = {targetId}, filter = {filter}, valuesDict = {valuesDict}")
        servers = [(k, f"{v} ({k})") for k, v in self.found_servers.items()]
        self.logger.threaddebug(f"get_found_servers: servers = {servers}")
        return servers

    def get_camera_list(self, filter="", valuesDict=None, typeId="", targetId=0):
        self.logger.threaddebug(f"get_found_cameras: typeId = {typeId}, targetId = {targetId}, filter = {filter}, valuesDict = {valuesDict}")
        if "any" in filter:
            cameras = [("-1", "- Any Camera -")]
        elif "all" in filter:
            cameras = [("-1", "- All Cameras -")]
        else:
            cameras = []
        try:
            for k, v in self.camera_info.items():
                cameras.append((k, v["name"]))
        except Exception as err:
            pass
        cameras.sort(key=lambda tup: tup[1])
        self.logger.threaddebug(f"get_camera_list: cameras = {cameras}")
        return cameras

    # doesn't do anything, just needed to force other menus to dynamically refresh
    def menu_changed(self, valuesDict=None, typeId=None, devId=None):  # noqa
        self.logger.threaddebug(f"menuChanged: typeId = {typeId}, devId = {devId}, valuesDict = {valuesDict}")
        return valuesDict

    def menu_changed_server(self, valuesDict=None, typeId=None, devId=None):
        self.logger.threaddebug(f"menu_changed_server: input valuesDict = {valuesDict}")
        if address := valuesDict.get('address'):
            parts = address.split(':')
            valuesDict['ip_address'] = parts[0]
            valuesDict['port'] = parts[1]
        self.logger.threaddebug(f"menu_changed_server: return valuesDict = {valuesDict}")
        return valuesDict

    def menu_log_camera_info(self, *args):
        self.logger.info(f"{json.dumps(self.camera_info, sort_keys=True, indent=4)}")

    ########################################
    # Action callbacks
    ########################################

    def set_camera_enabled_action(self, plugin_action, device, callerWaitingForResult):
        self.logger.debug(f"{device.name}: set_camera_enabled_action for {device.address}, enabled = {plugin_action.props['camera_enable']}")

        server_id, camera_num = device.address.split(':')
        camera_num = str(int(camera_num))   # remove leading zero
        server_dev = indigo.devices[self.spy_devices[server_id]]
        token = b64encode(bytes(f"{server_dev.pluginProps['username']}:{server_dev.pluginProps['password']}", "utf-8")).decode()
        enabled = bool(plugin_action.props["camera_enable"])

        url = f"http://{server_dev.address}/settings-camera?auth={token}"
        data = f"cameraNum={camera_num}&enabled={enabled}"
        self.logger.debug(f"set_camera_enabled_action: url = {url}, data = {data}")
        ret = requests.post(url, data=data)
        self.logger.debug(f"set_camera_enabled_action: result = {ret}")

    def set_arm_mode_action(self, plugin_action, device, callerWaitingForResult):
        self.logger.debug(f"{device.name}: set_arm_mode_action for {device.address}, camera_mode = {plugin_action.props['camera_mode']}, mode_enable = {plugin_action.props['camera_enable']}")

        server_id, camera_num = device.address.split(':')
        camera_num = str(int(camera_num))   # remove leading zero
        server_dev = indigo.devices[self.spy_devices[server_id]]
        token = b64encode(bytes(f"{server_dev.pluginProps['username']}:{server_dev.pluginProps['password']}", "utf-8")).decode()

        mode = plugin_action.props["camera_mode"]
        enabled = bool(plugin_action.props["camera_enable"])

#        cam_uri = f"{self._base_url}/setSchedule?cameraNum={camera_id}&schedule={schedule}&override=0&mode={rec_mode}&auth={self._token}"

        url = f"http://{server_dev.address}/settings-camera?auth={token}"
        data = f"cameraNum={camera_num}&enabled={enabled}"
        self.logger.debug(f"set_arm_mode_action: url = {url}, data = {data}")
        ret = requests.post(url, data=data)
        self.logger.debug(f"set_arm_mode_action: result = {ret}")

