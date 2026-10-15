import QtQuick
import QtQuick.Controls
import QtQuick.Shapes
import "../theme"

Button {
    id: root
    property string symbol: "minimize"
    property bool destructive: false
    readonly property color hoverColor: symbol === "close"
        ? Theme.danger
        : symbol === "maximize" ? Theme.success : Theme.blue
    // Symbol geometry in a 14x14 design space, as vector paths.
    readonly property string symbolPath: symbol === "tiny"
        ? "M1.8 3.2 H12.2 V10.8 H1.8 Z M4.5 13 L9.5 13"
        : symbol === "expand"
            ? "M1.8 1.8 H12.2 V12.2 H1.8 Z M5 7 L9.5 7 M7.25 4.75 L7.25 9.25"
            : symbol === "minimize"
                ? "M2 10.5 L12 10.5"
                : symbol === "maximize"
                    ? "M2.5 2.5 H11.5 V11.5 H2.5 Z"
                    : "M3 3 L11 11 M11 3 L3 11"

    implicitWidth: 34
    implicitHeight: 28
    hoverEnabled: true
    padding: 0
    ToolTip.visible: hovered
    ToolTip.delay: 500
    ToolTip.text: symbol === "close"
        ? I18n.t("close", "Close")
        : symbol === "maximize"
            ? I18n.t("maximize", "Maximize")
            : symbol === "tiny"
                ? I18n.t("tiny_mode", "Tiny mode")
                : symbol === "expand"
                    ? I18n.t("full_mode", "Full mode")
                    : I18n.t("minimize", "Minimize")

    contentItem: Item {
        // Shape renders pure geometry: no canvas texture is allocated and
        // hover recoloring is a uniform-color change, not a re-upload.
        Shape {
            anchors.centerIn: parent
            width: 14
            height: 14

            ShapePath {
                strokeColor: root.hovered ? root.hoverColor : Theme.textMuted
                strokeWidth: 1.35
                capStyle: ShapePath.RoundCap
                joinStyle: ShapePath.RoundJoin
                fillColor: "transparent"
                PathSvg { path: root.symbolPath }
            }
        }
    }

    background: Rectangle {
        color: root.hovered
            ? Qt.rgba(
                root.hoverColor.r,
                root.hoverColor.g,
                root.hoverColor.b,
                0.13
            )
            : "transparent"
        radius: 9
        scale: root.down ? 0.9 : 1
        Behavior on color {
            ColorAnimation { duration: Theme.animationFast }
        }
        Behavior on scale {
            NumberAnimation { duration: Theme.animationFast }
        }
    }
}
