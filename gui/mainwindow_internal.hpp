#pragma once
/// Helpers shared by the MainWindow sources (mainwindow*.cpp,
/// scanresults_model.cpp, addresslist_model.cpp). Not for other files.

#include "gui/mainwindow.hpp"

#include <QJsonArray>
#include <QString>
#include <cstddef>
#include <cstdint>

namespace ce::gui::mainwindow_detail {

// The address list's value refresh (and target-exit check). Not the Memory
// Viewer's "memview/refreshMs" setting: saving Settings stored that key's
// 2000 ms default and slowed this list and exit detection fourfold.
inline constexpr int kValueRefreshMs = 500;

QString foundLabelText(size_t count);
QString formatListAddress(uintptr_t address);
QJsonArray cheatEntriesToJson(const ce::CheatTable& table);
ScanCompare mapScanType(int index);
ValueType mapValueType(int index);
bool validRecordFormats(const QJsonArray& entries);

} // namespace ce::gui::mainwindow_detail
