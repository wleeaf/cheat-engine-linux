#include "gui/aboutdialog.hpp"

#include <QDialogButtonBox>
#include <QLabel>
#include <QTabWidget>
#include <QTextBrowser>
#include <QVBoxLayout>

namespace ce::gui {

AboutDialog::AboutDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("About Cheat Engine for Linux"));
    auto* layout = new QVBoxLayout(this);
    tabs_ = new QTabWidget(this);
    layout->addWidget(tabs_);

    auto* about = new QLabel(QString(tr(
        "<h2 style='margin-bottom:2px'>Cheat Engine for Linux</h2>"
        "<p style='margin-top:0'>Version %1</p>"
        "<p>A memory scanner, debugger and code injection tool for native Linux, "
        "Wine and Proton programs.</p>"
        "<p>Free and open source under the MIT license.</p>"
        "<p><a href='https://github.com/wleeaf/cheat-engine-linux'>Website</a> · "
        "<a href='https://github.com/wleeaf/cheat-engine-linux/issues'>Report a problem</a></p>"))
        .arg(CECORE_VERSION));
    about->setTextFormat(Qt::RichText);
    about->setOpenExternalLinks(true);
    about->setWordWrap(true);
    about->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    about->setContentsMargins(12, 12, 12, 12);
    tabs_->addTab(about, tr("About"));

    credits_ = QString(tr(
        "<p>Modelled on <a href='https://github.com/cheat-engine/cheat-engine'>Cheat Engine</a> "
        "by Eric Heijnen (Dark Byte) and its contributors: its windows, its Lua API "
        "and its cheat table format are the reference. No Cheat Engine code is used.</p>"
        "<p>Built with:</p>"
        "<ul>"
        "<li><a href='https://www.qt.io'>Qt</a> %1 (LGPL-3.0): the interface</li>"
        "<li><a href='https://www.capstone-engine.org'>Capstone</a> (BSD-3-Clause): the disassembler</li>"
        "<li><a href='https://www.keystone-engine.org'>Keystone</a> (GPL-2.0): the assembler</li>"
        "<li><a href='https://www.lua.org'>Lua</a> 5.3 (MIT): the scripting engine</li>"
        "<li><a href='https://github.com/leethomason/tinyxml2'>TinyXML-2</a> (zlib): cheat table files</li>"
        "<li><a href='https://sourceware.org/elfutils/'>elfutils libdw</a> (LGPL-3.0-or-later): "
        "debug information</li>"
        "<li><a href='https://zlib.net'>zlib</a> (zlib): compressed transfers</li>"
        "<li><a href='https://www.surina.net/soundtouch/'>SoundTouch</a> (LGPL-2.1), when present: "
        "pitch-corrected audio under the speedhack</li>"
        "</ul>"
        "<p>The license texts are installed under "
        "<code>share/licenses/cheat-engine-linux</code>.</p>")).arg(qVersion());
    auto* credits = new QTextBrowser(this);
    credits->setOpenExternalLinks(true);
    credits->setHtml(credits_);
    tabs_->addTab(credits, tr("Credits"));

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);
    resize(520, 420);
}

QString AboutDialog::creditsTextForTest() const { return credits_; }

} // namespace ce::gui
