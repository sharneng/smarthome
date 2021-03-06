/**
 *  MIMOlite Garage Door Opener
 *
 *  Copyright 2018-2020 Kenneth Xu
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
    definition (name: "MIMOlite Garage Door Opener", namespace: "sharneng", author: "Kenneth Xu", 
                importUrl: "https://raw.githubusercontent.com/sharneng/smarthome/master/Hubitat/driver/MIMOlite-Garage-Door-Opener.groovy") {
        capability "Actuator"
        capability "Configuration"
        capability "Contact Sensor"
        capability "Door Control"
        capability "Garage Door Control"
        capability "Lock"
        capability "Health Check"
        capability "Refresh"
        capability "Sensor"

        fingerprint mfr: "132", deviceId: "0x1000", prod:"1107", deviceJoinName: "MIMOLite Garage Door", 
            inClusters: "0x72,0x86,0x71,0x30,0x31,0x35,0x70,0x85,0x25,0x03"
    }

    preferences {
        inputTravelTime "openTravelTime", stringOpen
        inputTravelTime "closeTravelTime", stringClose
        input name: "logEnable", type: "bool", title: "Enable debug logging", defaultValue: false
        input name: "txtEnable", type: "bool", title: "Enable descriptionText logging", defaultValue: false
    }
}

def installed(){
    configure()
}

void logsOff(){
    if (txtEnable) log.info "debug logging disabled..."
    device.updateSetting("logEnable",[value:"false",type:"bool"])
}

def updated(){
    if (txtEnable) {
        log.info "Updated openTravelTime to ${normalizeTravelTime(openTravelTime)}, closeTravelTime to ${normalizeTravelTime(closeTravelTime)}"
        log.info "debug logging is: $logEnable"
        log.info "description logging is: $txtEnable"
    }
    if (logEnable) runIn(1800,logsOff)
}

def parse(String description) {
    def result = null
    if (description.startsWith("Err")) {
        if (state.sec) {
            result = createEvent(descriptionText:description, displayed:false)
        } else {
            result = createEvent(
                descriptionText: "This device failed to complete the network security key exchange. If you are unable to " +
                                 "control it via SmartThings, you must remove it from your network and add it again.",
                eventType: "ALERT",
                name: "secureInclusion",
                value: "failed",
                displayed: true,
            )
        }
    } else {
        def cmd = zwave.parse(description, [0x20: 1, 0x84: 1, 0x30: 1, 0x70: 1, 0x31: 5])
        if (cmd) {
            result = zwaveEvent(cmd)
        }
    }
    if (logEnable) log.debug "\"$description\" parsed to ${result.inspect()}"
    result
}

def zwaveEvent(hubitat.zwave.commands.sensorbinaryv1.SensorBinaryReport cmd)
{
    if (logEnable) log.debug "Got sensorBinaryReport event"
    def value = cmd.sensorValue ? stringOpen : stringClosed;
    def result = [createEvent(name: "contact", value: value)]
    if (!state.doorTraveling || value != stringOpen) result << createEvent(name: "door", value: value)
    result << createEvent(name: "lock", value: cmd.sensorValue ? "unlocked" : "locked")
    result
}

// sensorMultilevelReport is used to report the value of the analog voltage for SIG1
def zwaveEvent (hubitat.zwave.commands.sensormultilevelv5.SensorMultilevelReport cmd)
{
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
    createEvent(displayed: false, descriptionText: "$device.displayName: $cmd")
}

def unlock() {
    if (logEnable) log.debug "Got unlock command"
    operateDoor(stringOpen)
}

def lock() {
    if (logEnable) log.debug "Got lock command"
    operateDoor(stringClose)
}

def open() {
    if (logEnable) log.debug "Got open command"
    operateDoor(stringOpen)
}

def close() {
    if (logEnable) log.debug "Got close command"
    operateDoor(stringClose)
}

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
    if (logEnable) log.debug "Operation: $op, currentState: $currentDoorState, expectedState: $expectedState, nextState: $nextState, state: $state" +  
        ", voltage: " + state.voltage + ", doorTraveling: " + state.doorTraveling
    if (state.voltage == 0.0 && currentDoorState != stringClosed) {
        if(txtEnable) log.warn "Inconsistant door state and voltage. Refreshing..."
        doRefresh();
    } else if (currentDoorState == expectedState) {
        setDoorState(nextState)
        state.doorTraveling = true
        runIn(travelTime, syncDoorWithContact)
        delayBetween([
            secureCmd(zwave.basicV1.basicSet(value: 0xFF)), // Trigger the relay switch
            secureCmd(zwave.sensorMultilevelV5.sensorMultilevelGet())
        ], 200)
    } else {
        if (txtEnable) log.warn "Door is not in $expectedState state. Will not take action. Please try to refresh."
    }
}

def syncDoorWithContact() {
    if (logEnable) log.debug "Door travel timout. Updating door state with contact state"
    state.doorTraveling = false
    setDoorState(device.currentValue("contact"))
}

private def setDoorState(String value) {
    def event = createEvent(name: "door", value: value)
    if (logEnable) log.debug "sending event: $event"
    sendEvent(event)
}

def configure() {
    if(logEnable) log.debug "Got configure command" 
    runIn(1800,logsOff)
    //setting up to monitor power alarm and actuator duration
    delayBetween([
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
}

/**
 * PING is used by Device-Watch in attempt to reach the Device
 */
def ping() {
    if (logEnable) log.debug "Got ping command"
    doRefresh()
}

def refresh() {
    if (logEnable) log.debug "Got refresh command"
    doRefresh()
}

private def doRefresh() {
    state.doorTraveling = false
    state.voltage = null
    delayBetween([
        // requests a report of the anologue input voltage
        secureCmd(zwave.sensorMultilevelV5.sensorMultilevelGet()),
        // request a report of the sensor digital on/off state.
        secureCmd(zwave.sensorBinaryV1.sensorBinaryGet())
    ], 200)
}

private secureCmd(cmd) {
    if (getDataValue("zwaveSecurePairingComplete") == "true") {
        return zwave.securityV1.securityMessageEncapsulation().encapsulate(cmd).format()
    } else {
        return cmd.format()
    }	
}
