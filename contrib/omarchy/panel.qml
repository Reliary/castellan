// castellan Quickshell panel (P21.5, contrib — not shipped by the
// installer). A minimal status pill plus a freeze/thaw toggle.
//
// Install (Quickshell): drop this file in your shell's config and
// instantiate `CastellanPill`. It shells out to `castellan status
// --json` every 2s and starts the oneshot units for the toggle. No
// custom daemon protocol, no imports beyond Quickshell's own.
//
// States rendered:
//   no sessions          -> dim "castellan: idle"
//   N running, 0 frozen  -> "castellan: N"
//   any frozen           -> accent "castellan: N (M frozen)"
//
// The toggle starts castellan-freeze.service when nothing is frozen,
// castellan-thaw.service otherwise (both installed by `castellan
// service install`).

import Quickshell
import Quickshell.Io
import QtQuick

PanelWindow {
    id: root
    anchors.top: true
    anchors.right: true
    implicitWidth: pill.implicitWidth + 24
    implicitHeight: 34
    color: "transparent"

    property var status: ({})

    Process {
        id: poller
        command: ["castellan", "status", "--json"]
        running: true
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    root.status = JSON.parse(text)
                } catch (e) {
                    root.status = ({})
                }
            }
        }
    }

    Timer {
        interval: 2000
        running: true
        repeat: true
        onTriggered: {
            poller.running = false
            poller.running = true
        }
    }

    Process {
        id: toggle
        command: []
    }

    function counts() {
        const s = root.status.sessions || []
        let frozen = 0
        for (const x of s) if (x.state === "frozen") frozen++
        return { total: s.length, frozen: frozen }
    }

    Rectangle {
        id: pill
        anchors.centerIn: parent
        implicitWidth: label.implicitWidth + 20
        implicitHeight: 26
        radius: 13
        color: root.counts().frozen > 0 ? "#7a1f1f" : "#1f1f1f"

        Text {
            id: label
            anchors.centerIn: parent
            color: "#e8e8e8"
            font.pixelSize: 13
            text: {
                const c = root.counts()
                if (c.total === 0) return "castellan: idle"
                if (c.frozen > 0) return "castellan: " + c.total + " (" + c.frozen + " frozen)"
                return "castellan: " + c.total
            }
        }

        MouseArea {
            anchors.fill: parent
            onClicked: {
                const c = root.counts()
                toggle.command = ["systemctl", "--user", "start",
                    c.frozen > 0 ? "castellan-thaw.service" : "castellan-freeze.service"]
                toggle.running = true
            }
        }
    }
}
