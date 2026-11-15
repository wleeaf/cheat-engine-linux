#pragma once
/// Upper-case hex as Cheat Engine shows addresses and values: no prefix,
/// zero-padded to `width` digits when given ("1A2B", upperHex(0x1A, 4) "001A").

#include <QString>

namespace ce::gui {

inline QString upperHex(quint64 value, int width = 0) {
    return QString("%1").arg(value, width, 16, QChar('0')).toUpper();
}

} // namespace ce::gui
