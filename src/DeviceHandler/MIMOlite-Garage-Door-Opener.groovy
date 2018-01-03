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
metadata {
    definition (name: "MIMOlite Garage Door Opener", namespace: "sharneng", author: "Kenneth Xu") {
        capability "Actuator"
        capability "Configuration"
        capability "Contact Sensor"
        capability "Door Control"
        capability "Garage Door Control"
        capability "Health Check"
        capability "Refresh"
        capability "Sensor"
        capability "Switch"
        capability "Voltage Measurement"

        fingerprint deviceId: "0x1000", inClusters: "0x72,0x86,0x71,0x30,0x31,0x35,0x70,0x85,0x25,0x03"
    }

    simulator {
        status "closed": "command: 9881, payload: 00 66 03 00"
        status "opening": "command: 9881, payload: 00 66 03 FE"
        status "open": "command: 9881, payload: 00 66 03 FF"
        status "closing": "command: 9881, payload: 00 66 03 FC"
        status "unknown": "command: 9881, payload: 00 66 03 FD"

        reply "988100660100": "command: 9881, payload: 00 66 03 FC"
        reply "9881006601FF": "command: 9881, payload: 00 66 03 FE"
    }

    preferences {
       input "openTravelTime", "number", title: "Garage door open travel time in seconds. Only Numbers 5 to 60 allowed.", description: "Numbers 5 to 60 allowed.", defaultValue: 16, required: false, displayDuringSetup: true
       input "closeTravelTime", "number", title: "Garage door close travel time in seconds. Only Numbers 5 to 60 allowed.", description: "Numbers 5 to 60 allowed.", defaultValue: 16, required: false, displayDuringSetup: true
    }    

    tiles {
        standardTile("toggle", "device.door", width: 2, height: 2) {
            state("unknown", label:'${name}', action:"refresh.refresh", icon:"st.doors.garage.garage-open", backgroundColor:"#ffffff")
            state("closed", label:'${name}', action:"door control.open", icon:"st.doors.garage.garage-closed", backgroundColor:"#00a0dc", nextState:"opening")
            state("open", label:'${name}', action:"door control.close", icon:"st.doors.garage.garage-open", backgroundColor:"#e86d13", nextState:"closing")
            state("opening", label:'${name}', icon:"st.doors.garage.garage-opening", backgroundColor:"#e86d13")
            state("closing", label:'${name}', icon:"st.doors.garage.garage-closing", backgroundColor:"#00a0dc")
            
        }
        standardTile("open", "device.door", inactiveLabel: false) {
            state "default", label:'open', action:"door control.open", icon:"st.doors.garage.garage-opening", backgroundColor:"#e86d13"
        }
        standardTile("close", "device.door", inactiveLabel: false) {
            state "default", label:'close', action:"door control.close", icon:"st.doors.garage.garage-closing", backgroundColor:"#00a0dc"
        }
        standardTile("refresh", "device.door", inactiveLabel: false, decoration: "flat") {
            state "default", label:'', action:"refresh.refresh", icon:"st.secondary.refresh"
        }
        valueTile("voltage", "device.voltage") {
            state "val", label:'${currentValue}v', unit:"v", defaultState: true , backgroundColors: [
                [value: 0.0, color: "#00a0dc"],
                [value: 2.5, color: "#e86d13"]
            ]
        }
        standardTile("configure", "device.configure", inactiveLabel: false, decoration: "flat") {
            state "configure", label:'', action:"configuration.configure", icon:"st.secondary.configure"
        }

        main "toggle"
        details(["toggle", "open", "close", "refresh", "voltage", "configure",])
    }
}

def installed(){
    configure()
}

def updated(){
    log.debug "Updated openTravelTime to ${getTravelTime(openTravelTime)}, closeTravelTime to ${getTravelTime(closeTravelTime)}"
}

def getTravelTime(int time) {
    time < 5 ? 5 : (time > 60 ? 60 : time)
}

def parse(String description) {
    def result = null
    if (description.startsWith("Err")) {
        if (state.sec) {
            result = createEvent(descriptionText:description, displayed:false)
        } else {
            result = createEvent(
                descriptionText: "This device failed to complete the network security key exchange. If you are unable to control it via SmartThings, you must remove it from your network and add it again.",
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
    def value = cmd.sensorValue ? "open" : "closed";
    def result = [createEvent(name: "contact", value: value)]
    if (!state.doorTraveling || value != "open") result << createEvent(name: "door", value: value)
    result << createEvent(name: "switch", value: cmd.sensorValue ? "on" : "off")
    result
}

def zwaveEvent (physicalgraph.zwave.commands.sensormultilevelv5.SensorMultilevelReport cmd) // sensorMultilevelReport is used to report the value of the analog voltage for SIG1
{
    log.debug "Got SensorMultilevelReport event"
    def ADCvalue = cmd.scaledSensorValue
    def volt = (((1.5338*(10**-16))*(ADCvalue**5)) - ((1.2630*(10**-12))*(ADCvalue**4)) + ((3.8111*(10**-9))*(ADCvalue**3)) - ((4.7739*(10**-6))*(ADCvalue**2)) + ((2.8558*(10**-3))*(ADCvalue)) - (2.2721*(10**-2)))
    def result = [createEvent(name: "voltage", value: volt.round(1))]
    if (state.doorTraveling) { // poll the voltage every second if door is traveling
        result << response(["delay 1000", zwave.sensorMultilevelV5.sensorMultilevelGet().format()])
    }
    result   
}

def zwaveEvent(physicalgraph.zwave.Command cmd) {
    createEvent(displayed: false, descriptionText: "$device.displayName: $cmd")
}

def on() {
    log.debug "Got on command"
    operateDoor("open")
}

def off() {
    log.debug "Got off command"
    operateDoor("close")
}

def open() {
    log.debug "Got open command"
    operateDoor("open")
}

def close() {
    log.debug "Got close command"
    operateDoor("close")
}

private def operateDoor(String op) {
    def travelTime
    def nextState
    def expectedState
    if (op == "open") {
        expectedState = "closed"
        nextState = "opening"
        travelTime = openTravelTime
    } else if (op == "close") {
        expectedState = "open"
        nextState = "closing"
        travelTime = closeTravelTime
    } else {
        debug.error "Unknow door operation: $op"
        return
    }
    if (device.currentState("door").value == expectedState) {
        setDoorState(nextState)
        state.doorTraveling = true
        runIn(getTravelTime(travelTime), syncDoorWithContact)
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
        zwave.associationV1.associationSet(groupingIdentifier:3, nodeId:[zwaveHubNodeId]).format(), //     FYI: Group 3: If a power dropout occurs, the MIMOlite will send an Alarm Command Class report 
                                                                                                    //    (if there is enough available residual power)
        zwave.associationV1.associationSet(groupingIdentifier:2, nodeId:[zwaveHubNodeId]).format(), // periodically send a multilevel sensor report of the ADC analog voltage to the input
        zwave.associationV1.associationSet(groupingIdentifier:4, nodeId:[zwaveHubNodeId]).format(), // when the input is digitally triggered or untriggered, snd a binary sensor report
        zwave.configurationV1.configurationSet(configurationValue: [5], parameterNumber: 11, size: 1).format() // set relay to wait 500ms before it cycles again / size should just be 1 (for 1 byte.)
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
        //zwave.switchBinaryV1.switchBinaryGet().format(), //requests a report of the relay to make sure that it changed (the report is used elsewhere, look for switchBinaryReport()
        zwave.sensorMultilevelV5.sensorMultilevelGet().format(), // requests a report of the anologue input voltage
        zwave.sensorBinaryV1.sensorBinaryGet().format() // request a report of the sensor digital on/off state.
    ])
}

