import QtQuick
import "../theme"

Item {
    id: root
    property url source: Qt.resolvedUrl("../../assets/logo.png")
    readonly property url fallbackSource:
        Qt.resolvedUrl("../../assets/logo.svg")
    property bool fallbackTried: false
    property real cornerRadius: width * 0.28

    implicitWidth: 42
    implicitHeight: 42

    Rectangle {
        anchors.fill: parent
        radius: root.cornerRadius
        color: Theme.accent
        visible: logo.status !== Image.Ready
        Text {
            anchors.centerIn: parent
            text: "P"
            color: "white"
            font.pixelSize: parent.width * 0.48
            font.weight: Font.Bold
        }
    }

    Image {
        id: logo
        anchors.fill: parent
        source: root.source
        fillMode: Image.PreserveAspectFit
        smooth: true
        mipmap: true
        // Never decode larger than 2x the displayed size: bounds the
        // texture and image memory regardless of the source resolution.
        sourceSize: Qt.size(width * 2, height * 2)
        onStatusChanged: {
            if (status === Image.Error && !root.fallbackTried) {
                root.fallbackTried = true
                root.source = root.fallbackSource
            }
        }
    }
}
