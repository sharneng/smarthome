/**
 *  MIMOlite Garage Door Opener
 *
 *  Copyright 2018 Kenneth Xu
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
private def getColorOpen()       { "#e86d13" }
private def getColorClose()      { "#00a0dc" }
private def getStringOpen()      { "open" }
private def getStringClose()     { "close" }
private def getStringClosed()    { "closed" }
private def getStringClosing()   { "closing" }
private def getStringOpening()   { "opening" }
private def getStringVoltage()   { "voltage" }
private def getStringUnknown()   { "unknown" }
private def getStringRefresh()   { "refresh" }
private def getStringConfigure() { "configure" }
private def getStringToggle()    { "toggle" }

private def inputTravelTime(String inputName, String action) {
    input "${inputName}", "number",
          title: "Garage door ${action} travel time in seconds. Only Numbers 5 to 60 allowed.",
          description: "Numbers 5 to 60 allowed.", defaultValue: 16, required: false, displayDuringSetup: true
}

metadata {
    definition (name: "MIMOlite Garage Door Opener", namespace: "sharneng", author: "Kenneth Xu") {
        capability "Actuator"
        capability "Configuration"
        capability "Contact Sensor"
        capability "Door Control"
        capability "Garage Door Control"
        capability "Lock"
        capability "Health Check"
        capability "Refresh"
        capability "Sensor"
        capability "Voltage Measurement"

        fingerprint deviceId: "0x1000", inClusters: "0x72,0x86,0x71,0x30,0x31,0x35,0x70,0x85,0x25,0x03"
    }

    simulator {
        status "Contact closed":  "command: 3003, payload: 00"
        status "Contact open":    "command: 3003, payload: FF"
        status "Voltage 2.5v":    "command: 3105, payload: 02 0A 09 DF"
        status "Voltage 1.0v":    "command: 3105, payload: 02 0A 05 5F"
        status "Voltage 0.0v":    "command: 3105, payload: 02 0A 00 13"

        reply "2001FF, delay 100, 31040000": "command: 3105, payload: 02 0A 00 13" // open/close -> sensorMultilevelGet 0.0v
        reply "delay 1000, 31040000":        "command: 3105, payload: 02 0A 00 13" // poll sensorMultilevelGet 0.0v
        reply "31040000, delay 100, 3002":   "command: 3003, payload: 00"     // refresh -> sensor closed
    }

    preferences {
        inputTravelTime "openTravelTime", stringOpen
        inputTravelTime "closeTravelTime", stringClose
    }

    tiles {
        standardTile(stringToggle, "device.door", width: 2, height: 2) {
            state(stringUnknown, label:'${name}', icon:"st.doors.garage.garage-open",    backgroundColor:"#ffffff",  action:stringRefresh)
            state(stringClosed,  label:'${name}', icon:"st.doors.garage.garage-closed",  backgroundColor:colorClose, action:stringOpen,  nextState:stringOpening)
            state(stringOpen,    label:'${name}', icon:"st.doors.garage.garage-open",    backgroundColor:colorOpen,  action:stringClose, nextState:stringClosing)
            state(stringOpening, label:'${name}', icon:"st.doors.garage.garage-opening", backgroundColor:colorOpen)
            state(stringClosing, label:'${name}', icon:"st.doors.garage.garage-closing", backgroundColor:colorClose)
        }
        standardTile(stringOpen, "device.door", inactiveLabel: false) {
            state "default", label:stringOpen,  icon:"st.doors.garage.garage-opening", backgroundColor:colorOpen,  action:stringOpen
        }
        standardTile(stringClose, "device.door", inactiveLabel: false) {
            state "default", label:stringClose, icon:"st.doors.garage.garage-closing", backgroundColor:colorClose, action:stringClose
        }
        standardTile(stringRefresh, "device.door", inactiveLabel: false, decoration: "flat") {
            state "default", label:'',          icon:"st.secondary.refresh", action:stringRefresh
        }
        valueTile(stringVoltage, "device.voltage") {
            state "val", label:'${currentValue}v', unit:"v", defaultState: true , backgroundColors: [
                [value: 0.0, color: colorClose],
                [value: 2.5, color: colorOpen]
            ]
        }
        standardTile(stringConfigure, "device.configure", inactiveLabel: false, decoration: "flat") {
            state stringConfigure, label:'', icon:"st.secondary.configure", action:stringConfigure
        }

        main stringToggle
        details([stringToggle, stringOpen, stringClose, stringRefresh, stringVoltage, stringConfigure])
    }
}

def installed(){
    configure()
}

def updated(){
    log.debug "Updated openTravelTime to ${normalizeTravelTime(openTravelTime)}, closeTravelTime to ${normalizeTravelTime(closeTravelTime)}"
}

def normalizeTravelTime(Integer time) {
	def t = (time == null ? 16 : time.value)
    t < 5 ? 5 : (t > 60 ? 60 : t)
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
    log.debug "\"$description\" parsed to ${result.inspect()}"
    result
}

def zwaveEvent(physicalgraph.zwave.commands.sensorbinaryv1.SensorBinaryReport cmd)
{
    log.debug "Got sensorBinaryReport event"
    def value = cmd.sensorValue ? stringOpen : stringClosed;
    def result = [createEvent(name: "contact", value: value)]
    if (!state.doorTraveling || value != stringOpen) result << createEvent(name: "door", value: value)
    result << createEvent(name: "lock", value: cmd.sensorValue ? "unlocked" : "locked")
    result
}

// sensorMultilevelReport is used to report the value of the analog voltage for SIG1
def zwaveEvent (physicalgraph.zwave.commands.sensormultilevelv5.SensorMultilevelReport cmd)
{
    log.debug "Got SensorMultilevelReport event"
    def ADCvalue = cmd.scaledSensorValue
    def volt = (((1.5338*(10**-16))*(ADCvalue**5)) -
               ((1.2630*(10**-12))*(ADCvalue**4)) +
               ((3.8111*(10**-9))*(ADCvalue**3)) -
               ((4.7739*(10**-6))*(ADCvalue**2)) +
               ((2.8558*(10**-3))*(ADCvalue)) -
               (2.2721*(10**-2)))
    def result = [createEvent(name: stringVoltage, value: volt.round(1))]
    if (state.doorTraveling) { // poll the voltage every second if door is traveling
        result << response(["delay 1000", zwave.sensorMultilevelV5.sensorMultilevelGet().format()])
    }
    result
}

def zwaveEvent(physicalgraph.zwave.Command cmd) {
    createEvent(displayed: false, descriptionText: "$device.displayName: $cmd")
}

def unlock() {
    log.debug "Got unlock command"
    operateDoor(stringOpen)
}

def lock() {
    log.debug "Got lock command"
    operateDoor(stringClose)
}

def open() {
    log.debug "Got open command"
    operateDoor(stringOpen)
}

def close() {
    log.debug "Got close command"
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
    if (device.currentState("voltage").value == 0.0 && device.currentState("door").value != stringClosed) {
        log.debug "Inconsistant door state and voltage. Refreshing...";
        doRefresh();
    } else if (device.currentState("door").value == expectedState) {
        setDoorState(nextState)
        state.doorTraveling = true
        runIn(normalizeTravelTime(travelTime), syncDoorWithContact)
        delayBetween([
            zwave.basicV1.basicSet(value: 0xFF).format(), // Tigger the relay switch
            zwave.sensorMultilevelV5.sensorMultilevelGet().format()
        ])
    } else {
        log.debug "Door is not in $expectedState state. Will not take action. Please try to refresh."
    }
}

def syncDoorWithContact() {
    log.debug "Door travel timout. Updating door state with contact state"
    state.doorTraveling = false
    setDoorState(device.currentState("contact").value)
}

private def setDoorState(String value) {
    def event = createEvent(name: "door", value: value)
    log.debug "sending event: $event"
    sendEvent(event)
}

def configure() {
    log.debug "Got configure command" //setting up to monitor power alarm and actuator duration

    delayBetween([
        // FYI: Group 3: If a power dropout occurs, the MIMOlite will send an Alarm Command Class report
        // (if there is enough available residual power)
        zwave.associationV1.associationSet(groupingIdentifier:3, nodeId:[zwaveHubNodeId]).format(),
        // periodically send a multilevel sensor report of the ADC analog voltage to the input
        zwave.associationV1.associationSet(groupingIdentifier:2, nodeId:[zwaveHubNodeId]).format(),
        // when the input is digitally triggered or untriggered, snd a binary sensor report
        zwave.associationV1.associationSet(groupingIdentifier:4, nodeId:[zwaveHubNodeId]).format(),
        // set relay to wait 500ms before it cycles again / size should just be 1 (for 1 byte.)
        zwave.configurationV1.configurationSet(configurationValue: [5], parameterNumber: 11, size: 1).format()
    ])
}

/**
 * PING is used by Device-Watch in attempt to reach the Device
 */
def ping() {
    log.debug "Got ping command"
    doRefresh()
}

def refresh() {
    log.debug "Got refresh command"
    doRefresh()
}

private def doRefresh() {
    state.doorTraveling = false
    delayBetween([
        // requests a report of the relay to make sure that it changed (the report is used elsewhere, look for switchBinaryReport()
        //zwave.switchBinaryV1.switchBinaryGet().format(),
        // requests a report of the anologue input voltage
        zwave.sensorMultilevelV5.sensorMultilevelGet().format(),
        // request a report of the sensor digital on/off state.
        zwave.sensorBinaryV1.sensorBinaryGet().format()
    ])
}
