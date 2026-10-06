#include "gui/gdbconnectiondialog.hpp"
#include <QCloseEvent>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QTimer>
#include <array>

namespace ce::gui {
GdbConnectionDialog::GdbConnectionDialog(QWidget* parent):QDialog(parent) {
    setWindowTitle("Connect to GDB / QEMU");
    setObjectName("gdbConnectionDialog");
    resize(530,330);
    auto* form=new QFormLayout(this);
    QSettings settings;
    host_=new QLineEdit(settings.value("network/gdbHost","127.0.0.1").toString());
    host_->setObjectName("gdbHost");
    port_=new QSpinBox;port_->setRange(1,65535);
    port_->setValue(settings.value("network/gdbPort",1234).toInt());port_->setObjectName("gdbPort");
    form->addRow("Host:",host_);form->addRow("Port:",port_);
    order_=new QComboBox;order_->setObjectName("gdbByteOrder");
    order_->addItem("From target (may be unknown)",static_cast<int>(ByteOrder::Unknown));
    order_->addItem("Little-endian",static_cast<int>(ByteOrder::Little));
    order_->addItem("Big-endian",static_cast<int>(ByteOrder::Big));
    width_=new QComboBox;width_->setObjectName("gdbPointerWidth");
    width_->addItem("From target",0);width_->addItem("4 bytes (32-bit pointers)",4);width_->addItem("8 bytes (64-bit pointers)",8);
    form->addRow("Data byte order:",order_);form->addRow("Program pointer width:",width_);
    start_=new QLineEdit;start_->setObjectName("gdbRangeStart");start_->setPlaceholderText("e.g. 0x40000000");
    size_=new QLineEdit;size_->setObjectName("gdbRangeSize");size_->setPlaceholderText("e.g. 0x1000");
    form->addRow("Scan range start:",start_);form->addRow("Scan range size:",size_);
    auto* explanation=new QLabel("The target must be stopped. Leave both range fields blank to use the stub's memory map. Addresses and sizes accept decimal or 0x-prefixed hex.");
    explanation->setWordWrap(true);form->addRow(explanation);
    status_=new QLabel;status_->setWordWrap(true);status_->setObjectName("gdbConnectionStatus");form->addRow(status_);
    auto* buttons=new QDialogButtonBox;
    connect_=buttons->addButton("Connect",QDialogButtonBox::AcceptRole);connect_->setObjectName("gdbConnect");
    cancel_=buttons->addButton(QDialogButtonBox::Cancel);form->addRow(buttons);
    connect(connect_,&QPushButton::clicked,this,&GdbConnectionDialog::connectTarget);
    connect(cancel_,&QPushButton::clicked,this,&GdbConnectionDialog::reject);
    poll_=new QTimer(this);poll_->setInterval(20);connect(poll_,&QTimer::timeout,this,&GdbConnectionDialog::poll);
}
GdbConnectionDialog::~GdbConnectionDialog() {
    if (pending_.valid()) {cancellation_.request_stop();pending_.wait();}
}
QString GdbConnectionDialog::endpoint() const {return QString("%1:%2").arg(host_->text().trimmed()).arg(port_->value());}
void GdbConnectionDialog::setBusy(bool busy) {
    for (auto* widget:std::array<QWidget*,7>{host_,port_,order_,width_,start_,size_,connect_}) widget->setEnabled(!busy);
}
void GdbConnectionDialog::connectTarget() {
    if (pending_.valid()) return;
    GdbProcessOptions options;
    options.byteOrder=static_cast<ByteOrder>(order_->currentData().toInt());
    options.pointerWidth=static_cast<uint8_t>(width_->currentData().toInt());
    const auto host=host_->text().trimmed();
    if (host.isEmpty()) {status_->setText("Enter a host.");return;}
    if (!start_->text().trimmed().isEmpty() || !size_->text().trimmed().isEmpty()) {
        bool startOk=false,sizeOk=false;
        const auto start=start_->text().trimmed().toULongLong(&startOk,0);
        const auto size=size_->text().trimmed().toULongLong(&sizeOk,0);
        if (!startOk || !sizeOk || !size || start>UINTPTR_MAX || size>UINTPTR_MAX-start) {
            status_->setText("Enter a valid numeric range start and positive size.");return;
        }
        options.regions.push_back({static_cast<uintptr_t>(start),static_cast<size_t>(size),MemProt::ReadWrite,MemType::Private,MemState::Committed,{}});
    }
    canceled_=false;cancellation_=std::stop_source{};options.cancellation=cancellation_.get_token();
    const auto port=static_cast<uint16_t>(port_->value());
    try {
        pending_=std::async(std::launch::async,[host=host.toStdString(),port,options]{return GdbProcessHandle::connect(host,port,options);});
    } catch (const std::exception& error) {status_->setText(QString::fromUtf8(error.what()));return;}
    setBusy(true);status_->setText("Connecting and reading the target description...");poll_->start();
}
void GdbConnectionDialog::poll() {
    if (!pending_.valid() || pending_.wait_for(std::chrono::milliseconds(0))!=std::future_status::ready) return;
    poll_->stop();setBusy(false);
    try {
        auto result=pending_.get();
        if (canceled_) {if (result) (*result)->disconnect();QDialog::reject();return;}
        if (!result) {status_->setText(QString::fromStdString(result.error()));return;}
        connected_=std::move(*result);
        QSettings settings;settings.setValue("network/gdbHost",host_->text().trimmed());settings.setValue("network/gdbPort",port_->value());
        accept();
    } catch (const std::exception& error) {
        if (canceled_) {QDialog::reject();return;}
        status_->setText(QString::fromUtf8(error.what()));
    }
}
void GdbConnectionDialog::reject() {
    if (pending_.valid()) {
        canceled_=true;cancellation_.request_stop();status_->setText("Canceling the connection...");
        return;
    }
    QDialog::reject();
}
void GdbConnectionDialog::closeEvent(QCloseEvent* event) {
    if (pending_.valid()) {reject();event->ignore();return;}
    QDialog::closeEvent(event);
}
}
