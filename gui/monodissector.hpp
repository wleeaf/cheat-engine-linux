#pragma once
/// Mono dissector window: browse a Mono/Unity target's assemblies -> classes ->
/// fields (with ground-truth offsets from the injected agent), filter by name,
/// and send a field to the address list as a `base+offset` expression.

#include "platform/process_api.hpp"
#include "analysis/mono_dissector.hpp"
#include "core/types.hpp"

#include <QMainWindow>
#include <QString>

class QTreeWidget;
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
    /// `type` is the mapped value type; `label` is "Class.field".
    void addFieldRequested(quint32 offset, int valueType, const QString& label);

public slots:
    /// Inject the agent into the target and populate the tree with the result.
    void runDissect();

private:
    void applyFilter(const QString& text);

    ce::ProcessHandle* proc_;
    ce::MonoDissection dissection_;
    QTreeWidget* tree_;
    QLineEdit* filter_;
    QLabel* status_;
};

/// Map a Mono type name ("System.Int32", "System.Single", …) to our ValueType.
ce::ValueType monoTypeToValueType(const QString& monoType);

} // namespace ce::gui
