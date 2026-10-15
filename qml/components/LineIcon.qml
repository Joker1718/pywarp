import QtQuick
import QtQuick.Shapes
import "../theme"

// Vector icon rendered as GPU geometry via Qt Quick Shapes.
// Unlike the previous Canvas implementation this allocates no per-instance
// image/texture and never needs repaint-on-recolor: only the geometry
// buffers exist, which matters on VRAM-constrained (256 MB) systems.
Item {
    id: root
    property string name: "overview"
    property color iconColor: Theme.textMuted
    property real strokeWidth: 1.8

    implicitWidth: 22
    implicitHeight: 22

    // Icon geometry in a 24x24 design space, then uniformly scaled.
    readonly property string pathData: {
        if (name === "overview")
            return "M3.5 3.5 H10.5 V10.5 H3.5 Z"
                + " M13.5 3.5 H20.5 V8 H13.5 Z"
                + " M3.5 13.5 H10.5 V20.5 H3.5 Z"
                + " M13.5 10.5 H20.5 V20.5 H13.5 Z"
        if (name === "network")
            return "M3.5 12 A8.5 8.5 0 1 0 20.5 12 A8.5 8.5 0 1 0 3.5 12"
                + " M8.8 12 A3.2 3.2 0 1 0 15.2 12 A3.2 3.2 0 1 0 8.8 12"
                + " M12 3.5 L12 8.8 M12 15.2 L12 20.5"
                + " M3.5 12 L8.8 12 M15.2 12 L20.5 12"
        if (name === "activity")
            return "M3 13 L6.5 13 L9 7 L13 18 L16 10.5 L18 13 L21 13"
        if (name === "advanced")
            return "M4 7 L20 7 M4 17 L20 17"
                + " M6.8 7 A2.2 2.2 0 1 0 11.2 7 A2.2 2.2 0 1 0 6.8 7"
                + " M13.8 17 A2.2 2.2 0 1 0 18.2 17 A2.2 2.2 0 1 0 13.8 17"
        if (name === "settings")
            return "M8.8 12 A3.2 3.2 0 1 0 15.2 12 A3.2 3.2 0 1 0 8.8 12"
                + " M3.8 12 A8.2 8.2 0 1 0 20.2 12 A8.2 8.2 0 1 0 3.8 12"
                + " M12 1.8 L12 3.8 M12 20.2 L12 22.2"
                + " M1.8 12 L3.8 12 M20.2 12 L22.2 12"
        if (name === "power")
            return "M6.9 6.84 A8 8 0 1 1 6.9 19.16 M12 2.5 L12 12"
        if (name === "stop")
            return "M6 6 H18 V18 H6 Z"
        if (name === "close")
            return "M6 6 L18 18 M18 6 L6 18"
        if (name === "shield")
            return "M12 2.5 L20 5.7 L19 13.8 Q18 18.5 12 21.5"
                + " Q6 18.5 5 13.8 L4 5.7 Z"
        if (name === "check")
            return "M4.5 12.5 L9.5 17.5 L19.5 6.5"
        if (name === "warning")
            return "M12 3 L21 20 L3 20 Z M12 8 L12 14"
        if (name === "arrow-up")
            return "M12 19 L12 5 L6.5 10.5 M12 5 L17.5 10.5"
        if (name === "arrow-down")
            return "M12 5 L12 19 L6.5 13.5 M12 19 L17.5 13.5"
        if (name === "refresh")
            return "M18.93 9.08 A7.5 7.5 0 1 1 13.17 4.59"
                + " M18.8 4.7 L19.6 9.1 L15.3 8.2"
        return ""
    }

    // The warning icon additionally fills its exclamation dot.
    readonly property bool fillDot: name === "warning"
    readonly property string dotPath:
        "M11.3 17.2 A0.7 0.7 0 1 0 12.7 17.2 A0.7 0.7 0 1 0 11.3 17.2"

    Shape {
        anchors.centerIn: parent
        width: 24
        height: 24
        scale: root.width / 24

        ShapePath {
            strokeColor: root.iconColor
            strokeWidth: root.strokeWidth
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            fillColor: "transparent"
            PathSvg { path: root.pathData }
        }

        ShapePath {
            strokeColor: "transparent"
            fillColor: root.iconColor
            PathSvg { path: root.fillDot ? root.dotPath : "" }
        }
    }
}
