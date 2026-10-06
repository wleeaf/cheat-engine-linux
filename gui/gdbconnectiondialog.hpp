#pragma once
#include "platform/gdb_process.hpp"
#include <QDialog>
#include <future>

class QLineEdit;
class QSpinBox;
class QComboBox;
class QLabel;
class QPushButton;
class QTimer;

namespace ce::gui {
class GdbConnectionDialog final : public QDialog {
public:
    explicit GdbConnectionDialog(QWidget* parent=nullptr);
    ~GdbConnectionDialog() override;
    std::unique_ptr<GdbProcessHandle> takeProcess() {return std::move(connected_);}
    QString endpoint() const;
    void reject() override;
protected:
    void closeEvent(QCloseEvent* event) override;
private:
    void connectTarget();
    void poll();
    void setBusy(bool busy);
    QLineEdit* host_;
    QSpinBox* port_;
    QComboBox* order_;
    QComboBox* width_;
    QLineEdit* start_;
    QLineEdit* size_;
    QLabel* status_;
    QPushButton* connect_;
    QPushButton* cancel_;
    QTimer* poll_;
    std::stop_source cancellation_;
    bool canceled_=false;
    std::future<std::expected<std::unique_ptr<GdbProcessHandle>,std::string>> pending_;
    std::unique_ptr<GdbProcessHandle> connected_;
};
}
