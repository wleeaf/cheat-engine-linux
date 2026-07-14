#include "gui/scripteditor.hpp"
#include "gui/theme.hpp"
#include "core/aa_templates.hpp"
#include "core/injection_gen.hpp"
#include "arch/disassembler.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QFont>
#include <QLabel>
#include <QToolBar>
#include <QToolButton>
#include <QMenu>
#include <QMessageBox>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QInputDialog>
#include <QSyntaxHighlighter>
#include <QRegularExpression>

namespace ce::gui {

// Syntax highlighter for auto-assembler scripts: directives, AA commands,
// registers, numbers, labels, strings, and // + { } comments.
class AaHighlighter : public QSyntaxHighlighter {
public:
    explicit AaHighlighter(QTextDocument* doc) : QSyntaxHighlighter(doc) {
        // Token colors follow the active theme (dark pastels or light inks) so the
        // editor is readable in both, rather than being tuned only for a dark bg.
        const ce::gui::EditorPalette pal = ce::gui::editorPalette();
        auto fmt = [](const QColor& c, bool bold = false) {
            QTextCharFormat f; f.setForeground(c);
            if (bold) f.setFontWeight(QFont::Bold); return f;
        };
        commentFmt_ = fmt(pal.comment);
        QTextCharFormat directive = fmt(pal.directive, true);
        QTextCharFormat keyword   = fmt(pal.keyword, true);
        QTextCharFormat reg       = fmt(pal.reg);
        QTextCharFormat number    = fmt(pal.number);
        QTextCharFormat label     = fmt(pal.label);
        QTextCharFormat str       = fmt(pal.string);

        auto add = [&](const QString& pat, const QTextCharFormat& f,
                       QRegularExpression::PatternOptions o = QRegularExpression::NoPatternOption) {
            rules_.push_back({QRegularExpression(pat, o), f});
        };
        // [ENABLE] / [DISABLE] and other {$...} directives
        add(R"(\[(ENABLE|DISABLE)\])", directive, QRegularExpression::CaseInsensitiveOption);
        add(R"(\{\$[A-Za-z]+\})", directive);
        // AA commands
        add(R"(\b(globalalloc|aobscanmodule|aobscan|registersymbol|unregistersymbol|fullaccess|createthread(andwait)?|loadbinary|loadlibrary|reassemble|readmem|dealloc|kalloc|alloc|label|define|assert|include|nop|db|dw|dd|dq)\b)",
            keyword, QRegularExpression::CaseInsensitiveOption);
        // x86-64 registers
        add(R"(\b([re]?[abcd]x|[re]?[sd]i|[re]?[bs]p|r(8|9|1[0-5])[dwb]?|[abcd][lh]|[er]?ip|xmm\d+)\b)",
            reg, QRegularExpression::CaseInsensitiveOption);
        // numbers (hex 0x.., bare hex, decimal, $offset)
        add(R"((\$?\b0x[0-9A-Fa-f]+\b|\$[0-9A-Fa-f]+\b|\b\d+\b))", number);
        // quoted strings
        add(R"("[^"]*")", str);
        // a leading label:  (word at start of a line ending in ':')
        add(R"(^\s*[A-Za-z_][\w.@+]*:)", label);
    }

protected:
    void highlightBlock(const QString& text) override {
        for (const auto& rule : rules_) {
            auto it = rule.re.globalMatch(text);
            while (it.hasNext()) {
                auto m = it.next();
                setFormat(m.capturedStart(), m.capturedLength(), rule.fmt);
            }
        }
        // Line comments: // to end of line (after other rules so they win).
        int slash = text.indexOf("//");
        if (slash >= 0) setFormat(slash, text.length() - slash, commentFmt_);

        // Multi-line { ... } brace comments via block state.
        setCurrentBlockState(0);
        int start = (previousBlockState() == 1) ? 0 : text.indexOf('{');
        while (start >= 0) {
            int end = text.indexOf('}', start);
            int len = (end < 0) ? (text.length() - start) : (end - start + 1);
            setFormat(start, len, commentFmt_);
            if (end < 0) { setCurrentBlockState(1); break; }
            start = text.indexOf('{', end + 1);
        }
    }

private:
    struct Rule { QRegularExpression re; QTextCharFormat fmt; };
    std::vector<Rule> rules_;
    QTextCharFormat commentFmt_;
};

ScriptEditor::ScriptEditor(ProcessHandle* proc, AutoAssembler* autoAsm, QWidget* parent)
    : QMainWindow(parent), proc_(proc), autoAsm_(autoAsm) {

    setWindowTitle("Auto Assembler");
    resize(700, 500);

    // Toolbar
    auto* toolbar = new QToolBar;
    executeBtn_ = new QPushButton("Execute");
    executeBtn_->setStyleSheet("font-weight: bold; color: green;");
    connect(executeBtn_, &QPushButton::clicked, this, &ScriptEditor::onExecute);

    disableBtn_ = new QPushButton("Disable");
    disableBtn_->setEnabled(false);
    connect(disableBtn_, &QPushButton::clicked, this, &ScriptEditor::onDisable);

    auto* checkBtn = new QPushButton("Syntax Check");
    connect(checkBtn, &QPushButton::clicked, this, &ScriptEditor::onCheck);

    auto* addTableBtn = new QPushButton("Add to Cheat Table");
    addTableBtn_ = addTableBtn;
    addTableBtn->setToolTip("Save this script as a cheat-table entry whose checkbox "
                            "enables/disables it.");
    connect(addTableBtn, &QPushButton::clicked, this, &ScriptEditor::onAddToTable);

    auto* loadBtn = new QPushButton("Load");
    connect(loadBtn, &QPushButton::clicked, this, [this]() {
        auto path = QFileDialog::getOpenFileName(this, "Load Script", "", "CE Scripts (*.cea *.asm);;All Files (*)");
        if (path.isEmpty()) return;
        QFile f(path);
        if (f.open(QIODevice::ReadOnly)) {
            editor_->setPlainText(QTextStream(&f).readAll());
        }
    });

    auto* saveBtn = new QPushButton("Save");
    connect(saveBtn, &QPushButton::clicked, this, [this]() {
        auto path = QFileDialog::getSaveFileName(this, "Save Script", "", "CE Scripts (*.cea);;All Files (*)");
        if (path.isEmpty()) return;
        QFile f(path);
        if (f.open(QIODevice::WriteOnly)) {
            QTextStream(&f) << editor_->toPlainText();
        }
    });

    toolbar->addWidget(executeBtn_);
    toolbar->addWidget(disableBtn_);
    toolbar->addSeparator();
    toolbar->addWidget(checkBtn);
    toolbar->addWidget(addTableBtn);
    toolbar->addSeparator();
    toolbar->addWidget(loadBtn);
    toolbar->addWidget(saveBtn);
    toolbar->addSeparator();

    // Templates menu — paste a CE-style skeleton into the editor.
    auto* templateBtn = new QToolButton;
    templateBtn->setText("Templates ▾");
    templateBtn->setPopupMode(QToolButton::InstantPopup);
    templateBtn->setToolTip("Insert a code template (Ctrl+I in Cheat Engine)");
    auto* templateMenu = new QMenu(templateBtn);

    // Auto code-injection: read+disassemble the live target at an address and
    // emit a ready-to-run script (original code relocated, original bytes as a
    // db array) — the automatic equivalent of CE's "Code injection".
    auto* autoInject = templateMenu->addAction("Code injection at address (auto)...");
    autoInject->setToolTip("Read the process at an address and generate a complete "
                           "injection with the original bytes filled in");
    connect(autoInject, &QAction::triggered, this, &ScriptEditor::onGenerateCodeInjection);
    templateMenu->addSeparator();

    for (const auto& t : ce::builtinAaTemplates()) {
        QString label = QString::fromStdString(t.name);
        auto* action = templateMenu->addAction(label);
        action->setToolTip(QString::fromStdString(t.description));
        QString body = QString::fromStdString(t.body);
        QString name = label;
        connect(action, &QAction::triggered, this, [this, body, name]() {
            if (!editor_->toPlainText().trimmed().isEmpty()) {
                auto answer = QMessageBox::question(this, "Insert template?",
                    QString("Replace the current script with the '%1' template?\n"
                            "Click No to insert at the cursor instead.").arg(name),
                    QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel,
                    QMessageBox::Yes);
                if (answer == QMessageBox::Cancel) return;
                if (answer == QMessageBox::Yes) {
                    editor_->setPlainText(body);
                    return;
                }
            }
            editor_->insertPlainText(body);
        });
    }
    templateBtn->setMenu(templateMenu);
    toolbar->addWidget(templateBtn);

    addToolBar(toolbar);

    // Main content: editor (top) + output (bottom)
    auto* splitter = new QSplitter(Qt::Vertical);

    editor_ = new QPlainTextEdit;
    editor_->setFont(QFont("Monospace", 10));
    new AaHighlighter(editor_->document());   // syntax coloring
    editor_->setPlaceholderText(
        "[ENABLE]\n"
        "// Your auto-assembler script here\n"
        "alloc(newmem, 1024)\n"
        "label(returnhere)\n"
        "\n"
        "newmem:\n"
        "  mov eax, 999\n"
        "  jmp returnhere\n"
        "\n"
        "[DISABLE]\n"
        "dealloc(newmem)\n"
    );
    splitter->addWidget(editor_);

    output_ = new QTextEdit;
    output_->setReadOnly(true);
    output_->setFont(QFont("Monospace", 9));
    output_->setMaximumHeight(150);
    // The console paints its own line colors, so it can't inherit the app
    // stylesheet; give it the theme's editor background/text (was hardcoded dark,
    // which stayed dark in light mode).
    {
        const ce::gui::EditorPalette pal = ce::gui::editorPalette();
        output_->setStyleSheet(QString("background: %1; color: %2;")
            .arg(pal.background.name(), pal.text.name()));
    }
    splitter->addWidget(output_);

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 1);
    setCentralWidget(splitter);
}

void ScriptEditor::setScript(const std::string& script) {
    editor_->setPlainText(QString::fromStdString(script));
}

void ScriptEditor::setTableButtonText(const QString& t) {
    if (addTableBtn_) addTableBtn_->setText(t);
}

void ScriptEditor::onExecute() {
    if (beforeExecute_) beforeExecute_();
    if (!proc_ || !autoAsm_) {
        output_->setTextColor(ce::gui::editorPalette().error);
        output_->append("No process selected!");
        return;
    }

    auto script = editor_->toPlainText().toStdString();
    output_->clear();
    output_->setTextColor(ce::gui::editorPalette().text);
    output_->append("Executing...");

    auto result = autoAsm_->execute(*proc_, script);

    for (auto& msg : result.log)
        output_->append(QString::fromStdString(msg));

    if (result.success) {
        output_->setTextColor(ce::gui::editorPalette().success);
        output_->append("Script executed successfully.");
        lastDisableInfo_ = result.disableInfo;
        enabled_ = true;
        executeBtn_->setEnabled(false);
        disableBtn_->setEnabled(true);
    } else {
        output_->setTextColor(ce::gui::editorPalette().error);
        output_->append("FAILED: " + QString::fromStdString(result.error));
    }
}

void ScriptEditor::onDisable() {
    if (beforeExecute_) beforeExecute_();
    if (!proc_ || !autoAsm_ || !enabled_) return;

    auto script = editor_->toPlainText().toStdString();
    output_->clear();
    output_->setTextColor(ce::gui::editorPalette().text);
    output_->append("Disabling...");

    auto result = autoAsm_->disable(*proc_, script, lastDisableInfo_);

    for (auto& msg : result.log)
        output_->append(QString::fromStdString(msg));

    if (result.success) {
        output_->setTextColor(ce::gui::editorPalette().success);
        output_->append("Script disabled.");
        enabled_ = false;
        executeBtn_->setEnabled(true);
        disableBtn_->setEnabled(false);
    }
}

void ScriptEditor::onGenerateCodeInjection() {
    if (!proc_) {
        QMessageBox::warning(this, "No process", "Attach to a process first.");
        return;
    }
    bool ok = false;
    QString text = QInputDialog::getText(this, "Code injection",
        "Address (hex) to inject at:", QLineEdit::Normal, "", &ok);
    if (!ok || text.trimmed().isEmpty()) return;

    // Accept an optional "0x" prefix (QString::toULongLong(base 16) does not
    // reliably strip it), so both "0x1234" and "1234" work.
    QString hexText = text.trimmed();
    if (hexText.startsWith("0x", Qt::CaseInsensitive)) hexText = hexText.mid(2);
    uintptr_t address = hexText.toULongLong(&ok, 16);
    if (!ok || address == 0) {
        QMessageBox::warning(this, "Bad address", "Enter a valid hex address.");
        return;
    }

    std::string genErr;
    std::string script = ce::generateInjectionScript(*proc_, address, /*aob=*/false, genErr);
    if (script.empty()) {
        QMessageBox::warning(this, "Code injection",
            QString::fromStdString(genErr.empty() ? "Could not generate a template here." : genErr));
        return;
    }

    if (!editor_->toPlainText().trimmed().isEmpty()) {
        auto answer = QMessageBox::question(this, "Replace script?",
            "Replace the current script with the generated injection?",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
        if (answer != QMessageBox::Yes) return;
    }
    editor_->setPlainText(QString::fromStdString(script));
    output_->clear();
    output_->setTextColor(ce::gui::editorPalette().success);
    output_->append("Generated code injection. Fill in the code at '// your code here'.");
}

void ScriptEditor::onAddToTable() {
    auto script = editor_->toPlainText();
    if (script.trimmed().isEmpty()) {
        QMessageBox::information(this, "Add to Cheat Table", "The script is empty.");
        return;
    }
    if (!addToTable_) {
        QMessageBox::warning(this, "Add to Cheat Table",
            "This editor isn't connected to a cheat table.");
        return;
    }
    bool ok = false;
    QString desc = QInputDialog::getText(this, "Add to Cheat Table",
        "Description for the table entry:", QLineEdit::Normal,
        defaultDescription_, &ok);
    if (!ok) return;
    addToTable_(desc, script);
    output_->setTextColor(ce::gui::editorPalette().success);
    output_->append("Saved to the cheat table. Toggle its checkbox to enable/disable.");
}

void ScriptEditor::onCheck() {
    auto script = editor_->toPlainText().toStdString();
    output_->clear();

    auto result = autoAsm_->check(script);
    for (auto& msg : result.log)
        output_->append(QString::fromStdString(msg));

    if (result.success) {
        output_->setTextColor(ce::gui::editorPalette().success);
        output_->append("Syntax check passed.");
    }
}

} // namespace ce::gui
