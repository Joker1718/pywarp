import QtQuick
import QtQuick.Controls
import QtQuick.Shapes
import "../theme"

ComboBox {
    id: root
    implicitHeight: 40
    leftPadding: I18n.rtl ? 34 : 12
    rightPadding: I18n.rtl ? 12 : 34
    font.pixelSize: 13
    LayoutMirroring.enabled: false
    LayoutMirroring.childrenInherit: true

    contentItem: Text {
        leftPadding: 0
        rightPadding: 0
        text: root.displayText
        font: root.font
        color: Theme.text
        horizontalAlignment: I18n.rtl ? Text.AlignRight : Text.AlignLeft
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
    }
    indicator: Item {
        width: 16
        height: 16
        x: I18n.rtl ? 12 : root.width - width - 12
        anchors.verticalCenter: parent.verticalCenter
        Shape {
            anchors.fill: parent
            ShapePath {
                strokeColor: Theme.textMuted
                strokeWidth: 1.6
                capStyle: ShapePath.RoundCap
                joinStyle: ShapePath.RoundJoin
                fillColor: "transparent"
                PathSvg { path: "M4 6 L8 10 L12 6" }
            }
        }
    }
    background: Rectangle {
        color: root.hovered ? Theme.surfaceHover : Theme.surfaceRaised
        radius: Theme.radiusSmall
        border.color: root.activeFocus ? Theme.accent : Theme.border
    }
    popup: Popup {
        y: root.height + 5
        width: root.width
        implicitHeight: Math.min(contentItem.implicitHeight + 8, 300)
        padding: 4
        LayoutMirroring.enabled: false
        LayoutMirroring.childrenInherit: true
        contentItem: ListView {
            clip: true
            implicitHeight: contentHeight
            model: root.popup.visible ? root.delegateModel : null
            currentIndex: root.highlightedIndex
            ScrollIndicator.vertical: ScrollIndicator {}
        }
        background: Rectangle {
            color: Theme.surface
            radius: Theme.radiusSmall
            border.color: Theme.border
        }
    }
    delegate: ItemDelegate {
        required property int index
        required property var modelData
        width: root.width - 8
        height: 38
        leftPadding: 10
        rightPadding: 10
        text: root.textRole ? model[root.textRole] : modelData
        highlighted: root.highlightedIndex === index
        contentItem: Text {
            text: parent.text
            color: Theme.text
            font.pixelSize: 13
            elide: Text.ElideRight
            horizontalAlignment: I18n.rtl
                ? Text.AlignRight : Text.AlignLeft
            verticalAlignment: Text.AlignVCenter
        }
        background: Rectangle {
            radius: 6
            color: parent.highlighted ? Theme.surfaceHover : "transparent"
        }
    }
}
