/**
 *  August Lock Pro Z-Wave Lock With Doorsense - Z-Wave Lock
 *
 *  Copyright 2022 Kenneth Xu
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 *
 */

/*
 * ported from https://github.com/rafaelborja/SmartThingsAugustPro/blob/master/devicetypes/rafaelborja/august-lock-pro-zwave-lock-with-doorsense.src/august-lock-pro-zwave-lock-with-doorsense.groovy
 */

// Constants
private def getStringOpen()      { "open" }
private def getStringClose()     { "close" }
private def getStringClosed()    { "closed" }
private def getStringClosing()   { "closing" }
private def getStringOpening()   { "opening" }

private def inputTravelTime(String inputName, String action) {
    input inputName, "number",
          title: "Garage door $action travel time in seconds.",
          description: "Only numbers between 5 to 60 are allowed.", defaultValue: 20, required: false, range: 5..60
}

metadata {
    definition (name: "August Lock Pro Zwave Lock with Doorsense", namespace: "sharneng", author: "Kenneth Xu") {
        capability "Actuator"
        capability "Lock"
        capability "Refresh"
        capability "Health Check"
        capability "Configuration"
        capability "Contact Sensor"
        capability "Sensor"

        fingerprint mfr: "831", deviceId: "0x0001", prod:"0001", deviceJoinName: "August Smart Lock Pro", 
            inClusters: "0x5E,0x55,0x98,0x9F"
    }

    preferences {
        input name: "logEnable", type: "bool", title: "Enable debug logging", defaultValue: false
        input name: "logsOffMinutes", type: number, defaultValue: 30, range: 0..10080, 
            title: "Turn off debug logging in minutes (one week maximal and 0 disables auto off)."
        input name: "txtEnable", type: "bool", title: "Enable descriptionText logging", defaultValue: false
    }
}


/**
 * Called on app installed
 */
def installed() {
	// Device-Watch pings if no device events received for 1 hour (checkInterval)
	sendEvent(name: "checkInterval", value: 1 * 60 * 60, displayed: false, data: [protocol: "zwave", hubHardwareId: device.hub.hardwareID, offlinePingable: "1"])
	
    //createContactChildDevice()
    
	scheduleInstalledCheck()
}


/**
 * Verify that we have actually received the lock's initial states.
 * If not, verify that we have at least requested them or request them,
 * and check again.
 */
def scheduleInstalledCheck() {
	runIn(120, installedCheck, [forceForLocallyExecuting: true])
}

def installedCheck() {
	if (device.currentState("lock") && device.currentState("battery")) {
		unschedule("installedCheck")
	} else {
		// We might have called updated() or configure() at some point but not have received a reply, so don't flood the network
		if (!state.lastLockDetailsQuery || secondsPast(state.lastLockDetailsQuery, 2 * 60)) {
			def actions = updated()

			if (actions) {
				sendHubCommand(actions.toHubAction())
			}
		}

		scheduleInstalledCheck()
	}
}

/**
 * Called on app uninstalled
 */
def uninstalled() {
	def deviceName = device.displayName
	log.debug "[DTH] Executing 'uninstalled()' for device ${device.displayName}"
    removeChildDevices(getChildDevices())
	sendEvent(name: "lockRemoved", value: device.id, isStateChange: true, displayed: false)
}

/**
 * Executed when the user taps on the 'Done' button on the device settings screen. Sends the values to lock.
 *
 * @return hubAction: The commands to be executed
 */
def updated() {
	// Device-Watch pings if no device events received for 1 hour (checkInterval)
	sendEvent(name: "checkInterval", value: 1 * 60 * 60, displayed: false, data: [protocol: "zwave", hubHardwareId: device.hub.hardwareID, offlinePingable: "1"])

	def hubAction = null
	try {
		def cmds = []
		if (!device.currentState("lock") || !device.currentState("battery") || !state.configured) {
			log.debug "Returning commands for lock operation get and battery get"
			if (!state.configured) {
				cmds << doConfigure()
			}
			cmds << refresh()
			cmds << reloadAllCodes()
			if (!state.MSR) {
				cmds << zwave.manufacturerSpecificV1.manufacturerSpecificGet().format()
			}
			if (!state.fw) {
				cmds << zwave.versionV1.versionGet().format()
			}
			hubAction = response(delayBetween(cmds, 30*1000))
		}
	} catch (e) {
		log.warn "updated() threw $e"
	}
	hubAction
}

/**
 * Configures the device to settings needed by SmarthThings at device discovery time
 *
 */
def configure() {
	log.debug "[DTH] Executing 'configure()' for device ${device.displayName}"
	def cmds = doConfigure()
	log.debug "Configure returning with commands := $cmds"
	cmds
}

/**
 * Returns the list of commands to be executed when the device is being configured/paired
 *
 */
def doConfigure() {
	log.debug "[DTH] Executing 'doConfigure()' for device ${device.displayName}"
	state.configured = true
	def cmds = []
	cmds << secure(zwave.doorLockV1.doorLockOperationGet())
	cmds << secure(zwave.batteryV1.batteryGet())
	if (isSchlageLock()) {
		cmds << secure(zwave.configurationV2.configurationGet(parameterNumber: getSchlageLockParam().codeLength.number))
	}
	cmds = delayBetween(cmds, 30*1000)

	state.lastLockDetailsQuery = now()

	log.debug "Do configure returning with commands := $cmds"
	cmds
}

/*
def parse(String description) {
    if (logEnable) log.debug "parse: $description"
    def result = null
    if (description.startsWith("Err")) {
        result = state.sec ?
            buildEvent(descriptionText:description, displayed:false) :
            buildEvent(name: "secureInclusion", value: "failed", type: "ALERT", displayed: true,
                descriptionText: "This device failed to complete the network security key exchange. If you are unable to " +
                                 "control it via Hubitat, you must remove it from your network and add it again.")
    } else {
        def cmd = zwave.parse(description, [0x20: 1, 0x84: 1, 0x30: 1, 0x70: 1, 0x31: 5])
        if (cmd) {
            result = zwaveEvent(cmd)
        }
    }
    if (logEnable) log.debug "parsed to ${result.inspect()}"
    result
}

def zwaveEvent(hubitat.zwave.commands.sensorbinaryv1.SensorBinaryReport cmd) {
    if (logEnable) log.debug "Got sensorBinaryReport event"
    def value = cmd.sensorValue ? stringOpen : stringClosed;
    
    def type = null;
    if (state.doorTraveling == null) state.doorTraveling = false
    else type = state.doorTraveling ? "digital" : "physical"
    
    def result = [buildEvent(name: "contact", value: value, type: type)]
    if (!state.doorTraveling || value != stringOpen) result << buildEvent(name: "door", value: value, type: type)
    result << buildEvent(name: "lock", value: cmd.sensorValue ? "unlocked" : "locked", type: type)
    result
}

// sensorMultilevelReport is used to report the value of the analog voltage for SIG1
def zwaveEvent (hubitat.zwave.commands.sensormultilevelv5.SensorMultilevelReport cmd) {
    if (logEnable) log.debug "Got SensorMultilevelReport event"
    def ADCvalue = cmd.scaledSensorValue
    state.voltage = (((1.5338*(10**-16))*(ADCvalue**5)) -
               ((1.2630*(10**-12))*(ADCvalue**4)) +
               ((3.8111*(10**-9))*(ADCvalue**3)) -
               ((4.7739*(10**-6))*(ADCvalue**2)) +
               ((2.8558*(10**-3))*(ADCvalue)) -
               (2.2721*(10**-2))).round(1)
    state.doorTraveling ? // poll the voltage every second if door is traveling
        response(["delay 1000", secureCmd(zwave.sensorMultilevelV5.sensorMultilevelGet())]) :
        [:]
}

def zwaveEvent(hubitat.zwave.Command cmd) {
    buildEvent(displayed: false, descriptionText: "$device.displayName: $cmd")
}
*/

/**
 * Responsible for parsing incoming device messages to generate events
 *
 * @param description: The incoming description from the device
 *
 * @return result: The list of events to be sent out
 *
 */
def parse(String description) {
	log.debug "[DTH] Executing 'parse(String description)' for device ${device.displayName} with description = $description"

	def result = null
	if (description.startsWith("Err")) {
		if (state.sec) {
			result = createEvent(descriptionText:description, isStateChange:true, displayed:false)
		} else {
			result = createEvent(
					descriptionText: "This lock failed to complete the network security key exchange. If you are unable to control it via SmartThings, you must remove it from your network and add it again.",
					eventType: "ALERT",
					name: "secureInclusion",
					value: "failed",
					displayed: true,
			)
		}
	} else {
		def cmd = zwave.parse(description, [ 0x98: 1, 0x62: 1, 0x63: 1, 0x71: 2, 0x72: 2, 0x80: 1, 0x85: 2, 0x86: 1 ])
		if (cmd) {
			result = zwaveEvent(cmd)
		}
	}
	log.info "[DTH] parse() - returning result=$result"
	result
}

/**
 * Responsible for parsing ConfigurationReport command
 *
 * @param cmd: The ConfigurationReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.configurationv2.ConfigurationReport cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(hubitat.zwave.commands.configurationv2.ConfigurationReport cmd)' with cmd = $cmd"
	if (isSchlageLock() && cmd.parameterNumber == getSchlageLockParam().codeLength.number) {
		def result = []
		def length = cmd.scaledConfigurationValue
		def deviceName = device.displayName
		log.debug "[DTH] Executing 'ConfigurationReport' for device $deviceName with code length := $length"
		def codeLength = device.currentValue("codeLength")
		if (codeLength && codeLength != length) {
			log.debug "[DTH] Executing 'ConfigurationReport' for device $deviceName - all codes deleted"
			result = allCodesDeletedEvent()
			result << createEvent(name: "codeChanged", value: "all deleted", descriptionText: "Deleted all user codes",
					isStateChange: true, data: [lockName: deviceName, notify: true,
												notificationText: "Deleted all user codes in $deviceName at ${location.name}"])
			result << createEvent(name: "lockCodes", value: util.toJson([:]), displayed: false, descriptionText: "'lockCodes' attribute updated")
		}
		result << createEvent(name:"codeLength", value: length, descriptionText: "Code length is $length", displayed: false)
		return result
	}
	return null
}

/**
 * Responsible for parsing SecurityMessageEncapsulation command
 *
 * @param cmd: The SecurityMessageEncapsulation command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.securityv1.SecurityMessageEncapsulation cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(hubitat.zwave.commands.securityv1.SecurityMessageEncapsulation)' with cmd = $cmd"
	def encapsulatedCommand = cmd.encapsulatedCommand([0x62: 1, 0x71: 2, 0x80: 1, 0x85: 2, 0x63: 1, 0x98: 1, 0x86: 1])
	if (encapsulatedCommand) {
		zwaveEvent(encapsulatedCommand)
	}
}

/**
 * Responsible for parsing NetworkKeyVerify command
 *
 * @param cmd: The NetworkKeyVerify command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.securityv1.NetworkKeyVerify cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(hubitat.zwave.commands.securityv1.NetworkKeyVerify)' with cmd = $cmd"
	createEvent(name:"secureInclusion", value:"success", descriptionText:"Secure inclusion was successful", isStateChange: true)
}

/**
 * Responsible for parsing SecurityCommandsSupportedReport command
 *
 * @param cmd: The SecurityCommandsSupportedReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.securityv1.SecurityCommandsSupportedReport cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(hubitat.zwave.commands.securityv1.SecurityCommandsSupportedReport)' with cmd = $cmd"
	state.sec = cmd.commandClassSupport.collect { String.format("%02X ", it) }.join()
	if (cmd.commandClassControl) {
		state.secCon = cmd.commandClassControl.collect { String.format("%02X ", it) }.join()
	}
	createEvent(name:"secureInclusion", value:"success", descriptionText:"Lock is securely included", isStateChange: true)
}

/**
 * Responsible for parsing DoorLockOperationReport command
 *
 * @param cmd: The DoorLockOperationReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.doorlockv1.DoorLockOperationReport cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(DoorLockOperationReport)' with cmd = $cmd"
	def result = []

	unschedule("followupStateCheck")
	unschedule("stateCheck")

	// DoorLockOperationReport is called when trying to read the lock state or when the lock is locked/unlocked from the DTH or the smart app
	def map = [ name: "lock" ]
	map.data = [ lockName: device.displayName ]
	/*if (isKeyweLock()) {
		map.value = cmd.doorCondition >> 1 ? "unlocked" : "locked"
		map.descriptionText = cmd.doorCondition >> 1 ? "Unlocked" : "Locked"
	} else*/ if (cmd.doorLockMode == 0xFF) {
        log.debug "doorCondition is $cmd.doorCondition"
        if (cmd.doorCondition == 0x01 || cmd.doorCondition == 0x00) {
             log.debug "[DTH] Door is closed"
             updateContactSensor("closed")
        } else {
             log.debug "[DTH] Door is open"
             updateContactSensor("open")
        }
		map.value = "locked"
		map.descriptionText = "Locked"
	} else if (cmd.doorLockMode >= 0x40) {
		map.value = "unknown"
		map.descriptionText = "Unknown state"
	} else if (cmd.doorLockMode == 0x01) {
		map.value = "unlocked with timeout"
		map.descriptionText = "Unlocked with timeout"
	}  else {
       if (cmd.doorLockMode == 0x00) {
           log.debug "[DTH] doorLockMode is 00x0"
           log.debug "[DTH]  doorCondition is $cmd.doorCondition"
       	   // 0x01 for open
           if (cmd.doorCondition == 0x01 || cmd.doorCondition == 0x00 || cmd.doorCondition == 0x03) {
             log.debug "Door is closed"
             updateContactSensor("closed")
           } else {
             log.debug "Door is open"
             // 0x02
             updateContactSensor("open")
           }
       }

		map.value = "unlocked"
		map.descriptionText = "Unlocked"
		if (state.assoc != zwaveHubNodeId) {
			result << response(secure(zwave.associationV1.associationSet(groupingIdentifier:1, nodeId:zwaveHubNodeId)))
			result << response(zwave.associationV1.associationSet(groupingIdentifier:2, nodeId:zwaveHubNodeId))
			result << response(secure(zwave.associationV1.associationGet(groupingIdentifier:1)))
		}
	}
	/*if (generatesDoorLockOperationReportBeforeAlarmReport()) {
		// we're expecting lock events to come after notification events, but for specific yale locks they come out of order
		runIn(3, "delayLockEvent", [data: [map: map]])
		return [:]
	} else {*/
		return result ? [createEvent(map), *result] : createEvent(map)
	//}
}

def delayLockEvent(data) {
	log.debug "Sending cached lock operation: $data.map"
	sendEvent(data.map)
}

/**
 * Responsible for parsing AlarmReport command
 *
 * @param cmd: The AlarmReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.alarmv2.AlarmReport cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(hubitat.zwave.commands.alarmv2.AlarmReport)' with cmd = $cmd"
	def result = []

	if (cmd.zwaveAlarmType == 6) {
		result = handleAccessAlarmReport(cmd)
	} else if (cmd.zwaveAlarmType == 7) {
		result = handleBurglarAlarmReport(cmd)
	} else if(cmd.zwaveAlarmType == 8) {
		result = handleBatteryAlarmReport(cmd)
	} else {
		result = handleAlarmReportUsingAlarmType(cmd)
	}

	result = result ?: null
	log.debug "[DTH] zwaveEvent(hubitat.zwave.commands.alarmv2.AlarmReport) returning with result = $result"
	result
}

/**
 * Responsible for handling Access AlarmReport command
 *
 * @param cmd: The AlarmReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
private def handleAccessAlarmReport(cmd) {
	log.debug "[DTH] Executing 'handleAccessAlarmReport' with cmd = $cmd"
	def result = []
	def map = null
	def codeID, changeType, lockCodes, codeName
	def deviceName = device.displayName
	// lockCodes = loadLockCodes()
	if (1 <= cmd.zwaveAlarmEvent && cmd.zwaveAlarmEvent < 10) {
		map = [ name: "lock", value: (cmd.zwaveAlarmEvent & 1) ? "locked" : "unlocked" ]
	}
	switch(cmd.zwaveAlarmEvent) {
		case 1: // Manually locked
			map.descriptionText = "Locked manually"
			map.data = [ method: (cmd.alarmLevel == 2) ? "keypad" : "manual" ]
			break
		case 2: // Manually unlocked
			map.descriptionText = "Unlocked manually"
			map.data = [ method: "manual" ]
			break
		case 3: // Locked by command
			map.descriptionText = "Locked"
			map.data = [ method: "command" ]
			break
		case 4: // Unlocked by command
			map.descriptionText = "Unlocked"
			map.data = [ method: "command" ]
			break
		/*case 5: // Locked with keypad
			if (cmd.eventParameter || cmd.alarmLevel) {
				codeID = readCodeSlotId(cmd)
				codeName = getCodeName(lockCodes, codeID)
				map.descriptionText = "Locked by \"$codeName\""
				map.data = [ codeId: codeID as String, usedCode: codeID, codeName: codeName, method: "keypad" ]
			} else {
				// locked by pressing the Schlage button
				map.descriptionText = "Locked manually"
				map.data = [ method: "keypad" ]
			}
			break
		case 6: // Unlocked with keypad
			if (cmd.eventParameter || cmd.alarmLevel) {
				codeID = readCodeSlotId(cmd)
				codeName = getCodeName(lockCodes, codeID)
				map.descriptionText = "Unlocked by \"$codeName\""
				map.data = [ codeId: codeID as String, usedCode: codeID, codeName: codeName, method: "keypad" ]
			}
			break*/
		case 7:
			map = [ name: "lock", value: "unknown", descriptionText: "Unknown state" ]
			map.data = [ method: "manual" ]
			break
		case 8:
			map = [ name: "lock", value: "unknown", descriptionText: "Unknown state" ]
			map.data = [ method: "command" ]
			break
		case 9: // Auto locked
			map = [ name: "lock", value: "locked", data: [ method: "auto" ] ]
			map.descriptionText = "Auto locked"
			break
		case 0xA:
			map = [ name: "lock", value: "unknown", descriptionText: "Unknown state" ]
			map.data = [ method: "auto" ]
			break
		case 0xB:
			map = [ name: "lock", value: "unknown", descriptionText: "Unknown state" ]
			break
		/*case 0xC: // All user codes deleted
			result = allCodesDeletedEvent()
			map = [ name: "codeChanged", value: "all deleted", descriptionText: "Deleted all user codes", isStateChange: true ]
			map.data = [notify: true, notificationText: "Deleted all user codes in $deviceName at ${location.name}"]
			result << createEvent(name: "lockCodes", value: util.toJson([:]), displayed: false, descriptionText: "'lockCodes' attribute updated")
			break
		case 0xD: // User code deleted
			if (cmd.eventParameter || cmd.alarmLevel) {
				codeID = readCodeSlotId(cmd)
				if (lockCodes[codeID.toString()]) {
					codeName = getCodeName(lockCodes, codeID)
					map = [ name: "codeChanged", value: "$codeID deleted", isStateChange: true ]
					map.descriptionText = "Deleted \"$codeName\""
					map.data = [ codeName: codeName, notify: true, notificationText: "Deleted \"$codeName\" in $deviceName at ${location.name}" ]
					result << codeDeletedEvent(lockCodes, codeID)
				}
			}
			break
		case 0xE: // Master or user code changed/set
			if (cmd.eventParameter || cmd.alarmLevel) {
				codeID = readCodeSlotId(cmd)
				if(codeID == 0 && isKwiksetLock()) {
					//Ignoring this AlarmReport as Kwikset reports codeID 0 when all slots are full and user tries to set another lock code manually
					//Kwikset locks don't send AlarmReport when Master code is set
					log.debug "Ignoring this alarm report in case of Kwikset locks"
					break
				}
				codeName = getCodeNameFromState(lockCodes, codeID)
				changeType = getChangeType(lockCodes, codeID)
				map = [ name: "codeChanged", value: "$codeID $changeType",  descriptionText: "${getStatusForDescription(changeType)} \"$codeName\"", isStateChange: true ]
				map.data = [ codeName: codeName, notify: true, notificationText: "${getStatusForDescription(changeType)} \"$codeName\" in $deviceName at ${location.name}" ]
				if(!isMasterCode(codeID)) {
					result << codeSetEvent(lockCodes, codeID, codeName)
				} else {
					map.descriptionText = "${getStatusForDescription('set')} \"$codeName\""
					map.data.notificationText = "${getStatusForDescription('set')} \"$codeName\" in $deviceName at ${location.name}"
				}
			}
			break
		case 0xF: // Duplicate Pin-code error
			if (cmd.eventParameter || cmd.alarmLevel) {
				codeID = readCodeSlotId(cmd)
				clearStateForSlot(codeID)
				map = [ name: "codeChanged", value: "$codeID failed", descriptionText: "User code is duplicate and not added",
						isStateChange: true, data: [isCodeDuplicate: true] ]
			}
			break
		case 0x10: // Tamper Alarm
		case 0x13:
			map = [ name: "tamper", value: "detected", descriptionText: "Keypad attempts exceed code entry limit", isStateChange: true, displayed: true ]
			break
		case 0x11: // Keypad busy
			map = [ descriptionText: "Keypad is busy" ]
			break
		case 0x12: // Master code changed
			codeName = getCodeNameFromState(lockCodes, 0)
			map = [ name: "codeChanged", value: "0 set", descriptionText: "${getStatusForDescription('set')} \"$codeName\"", isStateChange: true ]
			map.data = [ codeName: codeName, notify: true, notificationText: "${getStatusForDescription('set')} \"$codeName\" in $deviceName at ${location.name}" ]
			break
		case 0x18: // KeyWe manual unlock
			map = [ name: "lock", value: "unlocked", data: [ method: "manual" ] ]
			map.descriptionText = "Unlocked manually"
			break
		case 0x19: // KeyWe manual lock
			map = [ name: "lock", value: "locked", data: [ method: "manual" ] ]
			map.descriptionText = "Locked manually"
			break
		case 0xFE:
			// delegating it to handleAlarmReportUsingAlarmType
			return handleAlarmReportUsingAlarmType(cmd)*/
		default:
			// delegating it to handleAlarmReportUsingAlarmType
			return handleAlarmReportUsingAlarmType(cmd)
	}

	if (map) {
		if (map.data) {
			map.data.lockName = deviceName
		} else {
			map.data = [ lockName: deviceName ]
		}
		result << createEvent(map)
	}
	result = result.flatten()
	result
}

/**
 * Responsible for handling Burglar AlarmReport command
 *
 * @param cmd: The AlarmReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
private def handleBurglarAlarmReport(cmd) {
	log.debug "[DTH] Executing 'handleBurglarAlarmReport' with cmd = $cmd"
	def result = []
	def deviceName = device.displayName

	def map = [ name: "tamper", value: "detected" ]
	map.data = [ lockName: deviceName ]
	switch (cmd.zwaveAlarmEvent) {
		case 0:
			map.value = "clear"
			map.descriptionText = "Tamper alert cleared"
			break
		case 1:
		case 2:
			map.descriptionText = "Intrusion attempt detected"
			break
		case 3:
			map.descriptionText = "Covering removed"
			break
		case 4:
			map.descriptionText = "Invalid code"
			break
		default:
			// delegating it to handleAlarmReportUsingAlarmType
			return handleAlarmReportUsingAlarmType(cmd)
	}

	result << createEvent(map)
	result
}

/**
 * Responsible for handling Battery AlarmReport command
 *
 * @param cmd: The AlarmReport command to be parsed
 *
 * @return The event(s) to be sent out
 */
private def handleBatteryAlarmReport(cmd) {
	log.debug "[DTH] Executing 'handleBatteryAlarmReport' with cmd = $cmd"
	def result = []
	def deviceName = device.displayName
	def map = null
	switch(cmd.zwaveAlarmEvent) {
		case 0x01: //power has been applied, check if the battery level updated
			result << response(secure(zwave.batteryV1.batteryGet()))
			break;
		case 0x0A:
			map = [ name: "battery", value: 1, descriptionText: "Battery level critical", displayed: true, data: [ lockName: deviceName ] ]
			break
		case 0x0B:
			map = [ name: "battery", value: 0, descriptionText: "Battery too low to operate lock", isStateChange: true, displayed: true, data: [ lockName: deviceName ] ]
			break
		default:
			// delegating it to handleAlarmReportUsingAlarmType
			return handleAlarmReportUsingAlarmType(cmd)
	}
	result << createEvent(map)
	result
}

/**
 * Responsible for handling AlarmReport commands which are ignored by Access & Burglar handlers
 *
 * @param cmd: The AlarmReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
private def handleAlarmReportUsingAlarmType(cmd) {
	log.debug "[DTH] Executing 'handleAlarmReportUsingAlarmType' with cmd = $cmd"
	def result = []
	def map = null
	def codeID, lockCodes, codeName
	def deviceName = device.displayName
	lockCodes = loadLockCodes()
	switch(cmd.alarmType) {
		case 9:
		case 17:
			map = [ name: "lock", value: "unknown", descriptionText: "Unknown state" ]
			break
		case 16: // Note: for levers this means it's unlocked, for non-motorized deadbolt, it's just unsecured and might not get unlocked
		case 19: // Unlocked with keypad
			map = [ name: "lock", value: "unlocked" ]
			if (cmd.alarmLevel != null) {
				codeID = readCodeSlotId(cmd)
				codeName = getCodeName(lockCodes, codeID)
				map.isStateChange = true // Non motorized locks, mark state changed since it can be unlocked multiple times
				map.descriptionText = "Unlocked by \"$codeName\""
				map.data = [ codeId: codeID as String, usedCode: codeID, codeName: codeName, method: "keypad" ]
			}
			break
		case 18: // Locked with keypad
			codeID = readCodeSlotId(cmd)
			map = [ name: "lock", value: "locked" ]
			// Kwikset lock reporting code id as 0 when locked using the lock keypad button
			if (isKwiksetLock() && codeID == 0) {
				map.descriptionText = "Locked manually"
				map.data = [ method: "manual" ]
			} else {
				codeName = getCodeName(lockCodes, codeID)
				map.descriptionText = "Locked by \"$codeName\""
				map.data = [ codeId: codeID as String, usedCode: codeID, codeName: codeName, method: "keypad" ]
			}
			break
		case 21: // Manually locked
			map = [ name: "lock", value: "locked", data: [ method: (cmd.alarmLevel == 2) ? "keypad" : "manual" ] ]
			map.descriptionText = "Locked manually"
			break
		case 22: // Manually unlocked
			map = [ name: "lock", value: "unlocked", data: [ method: "manual" ] ]
			map.descriptionText = "Unlocked manually"
			break
		case 23:
			map = [ name: "lock", value: "unknown", descriptionText: "Unknown state" ]
			map.data = [ method: "command" ]
			break
		case 24: // Locked by command
			map = [ name: "lock", value: "locked", data: [ method: "command" ] ]
			map.descriptionText = "Locked"
			break
		case 25: // Unlocked by command
			map = [ name: "lock", value: "unlocked", data: [ method: "command" ] ]
			map.descriptionText = "Unlocked"
			break
		case 26:
			map = [ name: "lock", value: "unknown", descriptionText: "Unknown state" ]
			map.data = [ method: "auto" ]
			break
		case 27: // Auto locked
			map = [ name: "lock", value: "locked", data: [ method: "auto" ] ]
			map.descriptionText = "Auto locked"
			break
		case 32: // All user codes deleted
			result = allCodesDeletedEvent()
			map = [ name: "codeChanged", value: "all deleted", descriptionText: "Deleted all user codes", isStateChange: true ]
			map.data = [notify: true, notificationText: "Deleted all user codes in $deviceName at ${location.name}"]
			result << createEvent(name: "lockCodes", value: util.toJson([:]), displayed: false, descriptionText: "'lockCodes' attribute updated")
			break
		case 33: // User code deleted
			codeID = readCodeSlotId(cmd)
			if (lockCodes[codeID.toString()]) {
				codeName = getCodeName(lockCodes, codeID)
				map = [ name: "codeChanged", value: "$codeID deleted", isStateChange: true ]
				map.descriptionText = "Deleted \"$codeName\""
				map.data = [ codeName: codeName, notify: true, notificationText: "Deleted \"$codeName\" in $deviceName at ${location.name}" ]
				result << codeDeletedEvent(lockCodes, codeID)
			}
			break
		case 38: // Non Access
			map = [ descriptionText: "A Non Access Code was entered at the lock", isStateChange: true ]
			break
		case 13:
		case 112: // Master or user code changed/set
			codeID = readCodeSlotId(cmd)
			if(codeID == 0 && isKwiksetLock()) {
				//Ignoring this AlarmReport as Kwikset reports codeID 0 when all slots are full and user tries to set another lock code manually
				//Kwikset locks don't send AlarmReport when Master code is set
				log.debug "Ignoring this alarm report in case of Kwikset locks"
				break
			}
			codeName = getCodeNameFromState(lockCodes, codeID)
			def changeType = getChangeType(lockCodes, codeID)
			map = [ name: "codeChanged", value: "$codeID $changeType", descriptionText:
					"${getStatusForDescription(changeType)} \"$codeName\"", isStateChange: true ]
			map.data = [ codeName: codeName, notify: true, notificationText: "${getStatusForDescription(changeType)} \"$codeName\" in $deviceName at ${location.name}" ]
			if(!isMasterCode(codeID)) {
				result << codeSetEvent(lockCodes, codeID, codeName)
			} else {
				map.descriptionText = "${getStatusForDescription('set')} \"$codeName\""
				map.data.notificationText = "${getStatusForDescription('set')} \"$codeName\" in $deviceName at ${location.name}"
			}
			break
		case 34:
		case 113: // Duplicate Pin-code error
			codeID = readCodeSlotId(cmd)
			clearStateForSlot(codeID)
			map = [ name: "codeChanged", value: "$codeID failed", descriptionText: "User code is duplicate and not added",
					isStateChange: true, data: [isCodeDuplicate: true] ]
			break
		case 130:  // Batteries replaced
			map = [ descriptionText: "Batteries replaced", isStateChange: true ]
			break
		case 131: // Disabled user entered at keypad
			map = [ descriptionText: "Code ${cmd.alarmLevel} is disabled", isStateChange: false ]
			break
		case 161: // Tamper Alarm
			if (cmd.alarmLevel == 2) {
				map = [ name: "tamper", value: "detected", descriptionText: "Front escutcheon removed", isStateChange: true ]
			} else {
				map = [ name: "tamper", value: "detected", descriptionText: "Keypad attempts exceed code entry limit", isStateChange: true, displayed: true ]
			}
			break
		case 167: // Low Battery Alarm
			if (!state.lastbatt || now() - state.lastbatt > 12*60*60*1000) {
				map = [ descriptionText: "Battery low", isStateChange: true ]
				result << response(secure(zwave.batteryV1.batteryGet()))
			} else {
				map = [ name: "battery", value: device.currentValue("battery"), descriptionText: "Battery low", isStateChange: true ]
			}
			break
		case 168: // Critical Battery Alarms
			map = [ name: "battery", value: 1, descriptionText: "Battery level critical", displayed: true ]
			break
		case 169: // Battery too low to operate
			map = [ name: "battery", value: 0, descriptionText: "Battery too low to operate lock", isStateChange: true, displayed: true ]
			break
		default:
			map = [ displayed: false, descriptionText: "Alarm event ${cmd.alarmType} level ${cmd.alarmLevel}" ]
			break
	}

	if (map) {
		if (map.data) {
			map.data.lockName = deviceName
		} else {
			map.data = [ lockName: deviceName ]
		}
		result << createEvent(map)
	}
	result = result.flatten()
	result
}

private boolean isSchlageLock() {
    return false
}

/**
 * Responsible for parsing UserCodeReport command
 *
 * @param cmd: The UserCodeReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.usercodev1.UserCodeReport cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(UserCodeReport)' with userIdentifier: ${cmd.userIdentifier} and status: ${cmd.userIdStatus}"
	def result = []
	// cmd.userIdentifier seems to be an int primitive type
	def codeID = cmd.userIdentifier.toString()
	def lockCodes = loadLockCodes()
	def map = [ name: "codeChanged", isStateChange: true ]
	def deviceName = device.displayName
	def userIdStatus = cmd.userIdStatus

	if (userIdStatus == hubitat.zwave.commands.usercodev1.UserCodeReport.USER_ID_STATUS_OCCUPIED ||
			(userIdStatus == hubitat.zwave.commands.usercodev1.UserCodeReport.USER_ID_STATUS_STATUS_NOT_AVAILABLE && cmd.user)) {

		def codeName

		// Schlage locks sends a blank/empty code during code creation/updation where as it sends "**********" during scanning
		// Some Schlage locks send "**********" during code creation also. The state check will work for them
		if ((!cmd.code || state["setname$codeID"]) && isSchlageLock()) {
			// this will be executed when the user tries to create/update a user code through the
			// smart app or manually on the lock. This is specific to Schlage locks.
			log.debug "[DTH] User code creation successful for Schlage lock"
			codeName = getCodeNameFromState(lockCodes, codeID)
			def changeType = getChangeType(lockCodes, codeID)

			map.value = "$codeID $changeType"
			map.isStateChange = true
			map.descriptionText = "${getStatusForDescription(changeType)} \"$codeName\""
			map.data = [ codeName: codeName, lockName: deviceName, notify: true, notificationText: "${getStatusForDescription(changeType)} \"$codeName\" in $deviceName at ${location.name}" ]
			if(!isMasterCode(codeID)) {
				result << codeSetEvent(lockCodes, codeID, codeName)
			} else {
				map.descriptionText = "${getStatusForDescription('set')} \"$codeName\""
				map.data.notificationText = "${getStatusForDescription('set')} \"$codeName\" in $deviceName at ${location.name}"
				map.data.lockName = deviceName
			}
		} else {
			// We'll land here during scanning of codes
			codeName = getCodeName(lockCodes, codeID)
			def changeType = getChangeType(lockCodes, codeID)
			if (!lockCodes[codeID]) {
				result << codeSetEvent(lockCodes, codeID, codeName)
			} else {
				map.displayed = false
			}
			map.value = "$codeID $changeType"
			map.descriptionText = "${getStatusForDescription(changeType)} \"$codeName\""
			map.data = [ codeName: codeName, lockName: deviceName ]
		}
	} else if(userIdStatus == 254 && isSchlageLock()) {
		// This is code creation/updation error for Schlage locks.
		// It should be OK to mark this as duplicate pin code error since in case the batteries are down, or lock is not in range,
		// or wireless interference is there, the UserCodeReport will anyway not be received.
		map = [ name: "codeChanged", value: "$codeID failed", descriptionText: "User code is not added", isStateChange: true,
				data: [ lockName: deviceName, isCodeDuplicate: true] ]
	} else {
		// We are using userIdStatus here because codeID = 0 is reported when user tries to set programming code as the user code
		if (codeID == "0" && userIdStatus == UserCodeReport.USER_ID_STATUS_AVAILABLE_NOT_SET && isSchlageLock()) {
			// all codes deleted for Schlage locks
			log.debug "[DTH] All user codes deleted for Schlage lock"
			result << allCodesDeletedEvent()
			map = [ name: "codeChanged", value: "all deleted", descriptionText: "Deleted all user codes", isStateChange: true,
					data: [ lockName: deviceName, notify: true,
							notificationText: "Deleted all user codes in $deviceName at ${location.name}"] ]
			lockCodes = [:]
			result << lockCodesEvent(lockCodes)
		} else {
			// code is not set
			if (lockCodes[codeID]) {
				def codeName = getCodeName(lockCodes, codeID)
				map.value = "$codeID deleted"
				map.descriptionText = "Deleted \"$codeName\""
				map.data = [ codeName: codeName, lockName: deviceName, notify: true, notificationText: "Deleted \"$codeName\" in $deviceName at ${location.name}" ]
				result << codeDeletedEvent(lockCodes, codeID)
			} else {
				map.value = "$codeID unset"
				map.displayed = false
				map.data = [ lockName: deviceName ]
			}
		}
	}

	clearStateForSlot(codeID)
	result << createEvent(map)

	if (codeID.toInteger() == state.checkCode) {  // reloadAllCodes() was called, keep requesting the codes in order
		if (state.checkCode + 1 > state.codes || state.checkCode >= 8) {
			state.remove("checkCode")  // done
			state["checkCode"] = null
			sendEvent(name: "scanCodes", value: "Complete", descriptionText: "Code scan completed", displayed: false)
		} else {
			state.checkCode = state.checkCode + 1  // get next
			result << response(requestCode(state.checkCode))
		}
	}
	if (codeID.toInteger() == state.pollCode) {
		if (state.pollCode + 1 > state.codes || state.pollCode >= 15) {
			state.remove("pollCode")  // done
			state["pollCode"] = null
		} else {
			state.pollCode = state.pollCode + 1
		}
	}

	result = result.flatten()
	result
}

/**
 * Responsible for parsing UsersNumberReport command
 *
 * @param cmd: The UsersNumberReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.usercodev1.UsersNumberReport cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(UsersNumberReport)' with cmd = $cmd"
	def result = [createEvent(name: "maxCodes", value: cmd.supportedUsers, displayed: false)]
	state.codes = cmd.supportedUsers
	if (state.checkCode) {
		if (state.checkCode <= cmd.supportedUsers) {
			result << response(requestCode(state.checkCode))
		} else {
			state.remove("checkCode")
			state["checkCode"] = null
		}
	}
	result
}

/**
 * Responsible for parsing AssociationReport command
 *
 * @param cmd: The AssociationReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.associationv2.AssociationReport cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(hubitat.zwave.commands.associationv2.AssociationReport)' with cmd = $cmd"
	def result = []
	if (cmd.nodeId.any { it == zwaveHubNodeId }) {
		state.remove("associationQuery")
		state["associationQuery"] = null
		result << createEvent(descriptionText: "Is associated")
		state.assoc = zwaveHubNodeId
		if (cmd.groupingIdentifier == 2) {
			result << response(zwave.associationV1.associationRemove(groupingIdentifier:1, nodeId:zwaveHubNodeId))
		}
	} else if (cmd.groupingIdentifier == 1) {
		result << response(secure(zwave.associationV1.associationSet(groupingIdentifier:1, nodeId:zwaveHubNodeId)))
	} else if (cmd.groupingIdentifier == 2) {
		result << response(zwave.associationV1.associationSet(groupingIdentifier:2, nodeId:zwaveHubNodeId))
	}
	result
}

/**
 * Responsible for parsing TimeGet command
 *
 * @param cmd: The TimeGet command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.timev1.TimeGet cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(hubitat.zwave.commands.timev1.TimeGet)' with cmd = $cmd"
	def result = []
	def now = new Date().toCalendar()
	if(location.timeZone) now.timeZone = location.timeZone
	result << createEvent(descriptionText: "Requested time update", displayed: false)
	result << response(secure(zwave.timeV1.timeReport(
			hourLocalTime: now.get(Calendar.HOUR_OF_DAY),
			minuteLocalTime: now.get(Calendar.MINUTE),
			secondLocalTime: now.get(Calendar.SECOND)))
	)
	result
}

/**
 * Responsible for parsing BasicSet command
 *
 * @param cmd: The BasicSet command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.basicv1.BasicSet cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(hubitat.zwave.commands.basicv1.BasicSet)' with cmd = $cmd"
	// The old Schlage locks use group 1 for basic control - we don't want that, so unsubscribe from group 1
	def result = [ createEvent(name: "lock", value: cmd.value ? "unlocked" : "locked") ]
	def cmds = [
			zwave.associationV1.associationRemove(groupingIdentifier:1, nodeId:zwaveHubNodeId).format(),
			"delay 1200",
			zwave.associationV1.associationGet(groupingIdentifier:2).format()
	]
	[result, response(cmds)]
}

/**
 * Responsible for parsing BatteryReport command
 *
 * @param cmd: The BatteryReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.batteryv1.BatteryReport cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(hubitat.zwave.commands.batteryv1.BatteryReport)' with cmd = $cmd"
	def map = [ name: "battery", unit: "%" ]
	if (cmd.batteryLevel == 0xFF) {
		map.value = 1
		map.descriptionText = "Has a low battery"
	} else {
		map.value = cmd.batteryLevel
		map.descriptionText = "Battery is at ${cmd.batteryLevel}%"
	}
	state.lastbatt = now()
	createEvent(map)
}

/**
 * Responsible for parsing ManufacturerSpecificReport command
 *
 * @param cmd: The ManufacturerSpecificReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.manufacturerspecificv2.ManufacturerSpecificReport cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(hubitat.zwave.commands.manufacturerspecificv2.ManufacturerSpecificReport)' with cmd = $cmd"
	def result = []
	def msr = String.format("%04X-%04X-%04X", cmd.manufacturerId, cmd.productTypeId, cmd.productId)
	updateDataValue("MSR", msr)
	result << createEvent(descriptionText: "MSR: $msr", isStateChange: false)
	result
}

/**
 * Responsible for parsing VersionReport command
 *
 * @param cmd: The VersionReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.versionv1.VersionReport cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(hubitat.zwave.commands.versionv1.VersionReport)' with cmd = $cmd"
	def fw = "${cmd.applicationVersion}.${cmd.applicationSubVersion}"
	updateDataValue("fw", fw)
	if (getDataValue("MSR") == "003B-6341-5044") {
		updateDataValue("ver", "${cmd.applicationVersion >> 4}.${cmd.applicationVersion & 0xF}")
	}
	def text = "${device.displayName}: firmware version: $fw, Z-Wave version: ${cmd.zWaveProtocolVersion}.${cmd.zWaveProtocolSubVersion}"
	createEvent(descriptionText: text, isStateChange: false)
}

/**
 * Responsible for parsing ApplicationBusy command
 *
 * @param cmd: The ApplicationBusy command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.applicationstatusv1.ApplicationBusy cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(hubitat.zwave.commands.applicationstatusv1.ApplicationBusy)' with cmd = $cmd"
	def msg = cmd.status == 0 ? "try again later" :
			cmd.status == 1 ? "try again in ${cmd.waitTime} seconds" :
					cmd.status == 2 ? "request queued" : "sorry"
	createEvent(displayed: true, descriptionText: "Is busy, $msg")
}

/**
 * Responsible for parsing ApplicationRejectedRequest command
 *
 * @param cmd: The ApplicationRejectedRequest command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.commands.applicationstatusv1.ApplicationRejectedRequest cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(hubitat.zwave.commands.applicationstatusv1.ApplicationRejectedRequest)' with cmd = $cmd"
	createEvent(displayed: true, descriptionText: "Rejected the last request")
}

/**
 * Responsible for parsing zwave command
 *
 * @param cmd: The zwave command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(hubitat.zwave.Command cmd) {
	log.debug "[DTH] Executing 'zwaveEvent(hubitat.zwave.Command)' with cmd = $cmd"
	createEvent(displayed: false, descriptionText: "$cmd")
}


/**
 * Executes unlock command on a lock
 */
def unlock() {
	log.debug "[DTH] Executing unlock() for device ${device.displayName}"
	lockAndCheck(DoorLockOperationSet.DOOR_LOCK_MODE_DOOR_UNSECURED)
}

/**
 * Executes unlock with timeout command on a lock
 */
def unlockWithTimeout() {
	log.debug "[DTH] Executing unlockWithTimeout() for device ${device.displayName}"
	lockAndCheck(DoorLockOperationSet.DOOR_LOCK_MODE_DOOR_UNSECURED_WITH_TIMEOUT)
}

/**
 * Executes lock and then check command with a delay on a lock
 */
def lockAndCheck(doorLockMode) {
	secureSequence([
			zwave.doorLockV1.doorLockOperationSet(doorLockMode: doorLockMode),
			zwave.doorLockV1.doorLockOperationGet()
	], 4200)
}

/**
 * Executes lock command on a lock
 */
def lock() {
	log.debug "[DTH] Executing lock() for device ${device.displayName}"
	lockAndCheck(DoorLockOperationSet.DOOR_LOCK_MODE_DOOR_SECURED)
}
/*
private def operateDoor(String op) {
    def travelTime
    def nextState
    def expectedState
    if (op == stringOpen) {
        expectedState = stringClosed
        nextState = stringOpening
        travelTime = openTravelTime
    } else if (op == stringClose) {
        expectedState = stringOpen
        nextState = stringClosing
        travelTime = closeTravelTime
    } else {
        debug.error "Unknow door operation: $op"
        return
    }
    def currentDoorState = device.currentValue("door")
    if (logEnable) log.debug "expectedState: $expectedState, nextState: $nextState. $state"
    if (state.voltage == 0.0 && currentDoorState != stringClosed) {
        log.warn "Inconsistant door state and voltage. Refreshing..."
        doRefresh();
    } else if (currentDoorState == expectedState) {
        sendEvent(buildEvent(name: "door", value: nextState, type: "digital"))
        state.doorTraveling = true
        runIn(travelTime, syncDoorWithContact)
        delayBetween([
            secureCmd(zwave.basicV1.basicSet(value: 0xFF)), // Trigger the relay switch
            secureCmd(zwave.sensorMultilevelV5.sensorMultilevelGet())
        ], 200)
    } else {
        log.warn "Door is not in $expectedState state. Will not take action. Please try to refresh."
    }
}

def syncDoorWithContact() {
    state.doorTraveling = false
    if (device.currentValue("contact") != device.currentValue("door")) {
        if (logEnable) log.debug "Door travel timout. Updating door state with contact state"
        sendEvent(buildEvent(name: "door", value: device.currentValue("contact"), type: "digital"))
    }
}

private Map buildEvent(Map properties) {
    def text = properties.descriptionText
    if (text == null) properties.descriptionText = text = "$device.displayName $properties.name is $properties.value"
    if (txtEnable) log.info "Event: $text"
    properties
}

def configure() {
    if (logEnable) log.debug "Got configure command" 
    doConfigure()
}

private def doConfigure() {
    if (logEnable && logsOffMinutes) runIn(logsOffMinutes*60,logsOff)
    //setting up to monitor power alarm and actuator duration
    def result = delayBetween([
        // FYI: Group 3: If a power dropout occurs, the MIMOlite will send an Alarm Command Class report
        // (if there is enough available residual power)
        secureCmd(zwave.associationV1.associationSet(groupingIdentifier:3, nodeId:[zwaveHubNodeId])),
        // periodically send a multilevel sensor report of the ADC analog voltage to the input
        secureCmd(zwave.associationV1.associationSet(groupingIdentifier:2, nodeId:[zwaveHubNodeId])),
        // when the input is digitally triggered or untriggered, send a binary sensor report
        secureCmd(zwave.associationV1.associationSet(groupingIdentifier:4, nodeId:[zwaveHubNodeId])),
        // set relay to wait 500ms before it cycles again / size should just be 1 (for 1 byte.)
        secureCmd(zwave.configurationV1.configurationSet(configurationValue: [5], parameterNumber: 11, size: 1))
    ], 200)
    if (logEnable) log.debug("configure: $result")
    result
}
*/
/**
 * PING is used by Device-Watch in attempt to reach the Device
 *//*
def ping() {
    if (logEnable) log.debug "Got ping command"
    doRefresh()
}

def refresh() {
    if (logEnable) log.debug "Got refresh command"
    doRefresh()
}

private def doRefresh() {
    state.clear()
    def result = delayBetween([
        // requests a report of the anologue input voltage
        secureCmd(zwave.sensorMultilevelV5.sensorMultilevelGet()),
        // request a report of the sensor digital on/off state.
        secureCmd(zwave.sensorBinaryV1.sensorBinaryGet())
    ], 200)
    if (logEnable) log.debug "refresh: $result"
    result
}
*/


/**
 * PING is used by Device-Watch in attempt to reach the Device
 */
def ping() {
	log.debug "[DTH] Executing ping() for device ${device.displayName}"
	runIn(30, followupStateCheck)
	secure(zwave.doorLockV1.doorLockOperationGet())
}

/**
 * Checks the door lock state. Also, schedules checking of door lock state every one hour.
 */
def followupStateCheck() {
	runEvery1Hour(stateCheck)
	stateCheck()
}

/**
 * Checks the door lock state
 */
def stateCheck() {
	sendHubCommand(new hubitat.device.HubAction(secure(zwave.doorLockV1.doorLockOperationGet())))
}

/**
 * Called when the user taps on the refresh button
 */
def refresh() {
	log.debug "[DTH] Executing refresh() for device ${device.displayName}"

	def cmds = secureSequence([zwave.doorLockV1.doorLockOperationGet(), zwave.batteryV1.batteryGet()])
	if (!state.associationQuery) {
		cmds << "delay 4200"
		cmds << zwave.associationV1.associationGet(groupingIdentifier:2).format()  // old Schlage locks use group 2 and don't secure the Association CC
		cmds << secure(zwave.associationV1.associationGet(groupingIdentifier:1))
		state.associationQuery = now()
	} else if (now() - state.associationQuery.toLong() > 9000) {
		cmds << "delay 6000"
		cmds << zwave.associationV1.associationSet(groupingIdentifier:2, nodeId:zwaveHubNodeId).format()
		cmds << secure(zwave.associationV1.associationSet(groupingIdentifier:1, nodeId:zwaveHubNodeId))
		cmds << zwave.associationV1.associationGet(groupingIdentifier:2).format()
		cmds << secure(zwave.associationV1.associationGet(groupingIdentifier:1))
		state.associationQuery = now()
	}
	state.lastLockDetailsQuery = now()

	cmds
}

/**
  * Updates door sense contact value.
  * @param value: "open" or "close"
  */
private updateContactSensor(value) {
	log.debug "[DTH] Updating contact sensor to ${value}"
    def current_state = device.currentState("contact")?.value
    def isStateChange = value != current_state
	sendEvent(name: "contact", value: value, descriptionText: "Door is ${value}", displayed: true, isStateChange: isStateChange)
    if (isStateChange) {
    	updateChildContactDevice(value)
    }
}

private secureCmd(cmd) {
    if (getDataValue("zwaveSecurePairingComplete") == "true") {
        return zwave.securityV1.securityMessageEncapsulation().encapsulate(cmd).format()
    } else {
        return cmd.format()
    }	
}

/**
 * Encapsulates a command
 *
 * @param cmd: The command to be encapsulated
 *
 * @returns ret: The encapsulated command
 */
private secure(hubitat.zwave.Command cmd) {
	secureCmd(cmd)
}

/**
 * Encapsulates list of command and adds a delay
 *
 * @param commands: The list of command to be encapsulated
 *
 * @param delay: The delay between commands
 *
 * @returns The encapsulated commands
 */
private secureSequence(commands, delay=4200) {
	delayBetween(commands.collect{ secure(it) }, delay)
}
