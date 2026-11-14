#pragma once
/// Mono dissector window: browse a Mono/Unity target's assemblies -> classes ->
/// fields (with ground-truth offsets from the injected agent), filter by name,
/// find a class's live objects, and send a field to the address list as a
/// `base+offset` expression (the base defaults to the chosen object).

#include "platform/process_api.hpp"
#include "analysis/mono_dissector.hpp"
#include "core/types.hpp"

#include <QMainWindow>
#include <QString>

class QTreeWidget;
class QTreeWidgetItem;
class QPoint;
class QLineEdit;
class QLabel;

namespace ce::gui {

class MonoDissectorWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MonoDissectorWindow(ce::ProcessHandle* proc, QWidget* parent = nullptr);

    /// Populate the tree from an already-parsed dissection (used by tests and by
    /// runDissect once injection completes).
    void setDissection(const ce::MonoDissection& d);

signals:
    /// A field was chosen for the address list. `offset` is within the object;
    /// `type` is the mapped value type; `label` is "Class.field"; `base` is the
    /// class's chosen object ("0x..."), or empty when none was chosen.
    void addFieldRequested(quint32 offset, int valueType, const QString& label, bool isStatic,
                           const QString& base);
    /// An object found by "Find instances" was double-clicked.
    void instanceActivated(quint64 address);

public slots:
    /// Inject the agent into the target and populate the tree with the result.
    void runDissect();

    /// Find the live objects of a class item's class (Mono only) and list
    /// them under it.
    void findInstances(QTreeWidgetItem* classItem);

private:
    void applyFilter(const QString& text);
    void showContextMenu(const QPoint& position);

    ce::ProcessHandle* proc_;
    ce::MonoDissection dissection_;
    bool liveMono_ = false;   // the tree came from the Mono agent, which can find objects
    QTreeWidget* tree_;
    QLineEdit* filter_;
    QLabel* status_;
};

/// Map a Mono type name ("System.Int32", "System.Single", …) to our ValueType.
ce::ValueType monoTypeToValueType(const QString& monoType);

} // namespace ce::gui
