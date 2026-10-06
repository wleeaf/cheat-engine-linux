#include "gui/scripteditor.hpp"
#include "gui/autoasmoperation.hpp"
#include "gui/theme.hpp"
#include "core/aa_templates.hpp"
#include "core/injection_gen.hpp"
#include "core/expression.hpp"
#include "symbols/elf_symbols.hpp"
#include <QVBoxLayout>
#include <QApplication>
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
#include <QSaveFile>
#include <QTextStream>
#include <QInputDialog>
#include <QSyntaxHighlighter>
#include <QRegularExpression>
#include <QCloseEvent>
#include <QPointer>
#include <QScopeGuard>
#include <algorithm>

namespace ce::gui {

// Syntax highlighter for auto-assembler scripts: directives, AA commands,
// registers, numbers, labels, strings, and // + { } comments.
class AaHighlighter : public QSyntaxHighlighter {
public:
    explicit AaHighlighter(QTextDocument* doc) : QSyntaxHighlighter(doc) {
        updateColors();
        connect(qApp, &QApplication::paletteChanged, this, [this]() { updateColors(); rehighlight(); });
    }

    void updateColors() {
        rules_.clear();
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
        stringFmt_ = str;
        directiveFmt_ = directive;

        auto add = [&](const QString& pat, const QTextCharFormat& f,
                       QRegularExpression::PatternOptions o = QRegularExpression::NoPatternOption) {
            rules_.push_back({QRegularExpression(pat, o), f});
        };
        // [ENABLE] / [DISABLE] and other {$...} directives
        add(R"(\[(ENABLE|DISABLE)\])", directive, QRegularExpression::CaseInsensitiveOption);
        add(R"(\{\$\s*[A-Za-z]+[^}]*\})", directive);
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
        setCurrentBlockState(0);
        int i = 0;
        if (previousBlockState() == 1) {
            int end = text.indexOf('}');
            setFormat(0, end < 0 ? text.size() : end + 1, commentFmt_);
            if (end < 0) { setCurrentBlockState(1); return; }
            i = end + 1;
        }
        while (i < text.size()) {
            if (text[i] == '\"' || text[i] == '\'') {
                int start = i;
                auto quote = text[i++];
                while (i < text.size() && text[i] != quote) {
                    if (text[i] == '\\' && i + 1 < text.size()) ++i;
                    ++i;
                }
                setFormat(start, std::min(i + 1, int(text.size())) - start, stringFmt_);
            } else if (text.mid(i, 2) == "//") {
                setFormat(i, text.size() - i, commentFmt_);
                break;
            } else if (text[i] == '{') {
                int end = text.indexOf('}', i);
                bool directive = text.mid(i, 2) == "{$";
                if (directive && end >= 0) setFormat(i, end - i + 1, directiveFmt_);
                if (!directive) {
                    setFormat(i, end < 0 ? text.size() - i : end - i + 1, commentFmt_);
                    if (end < 0) { setCurrentBlockState(1); break; }
                }
                if (end >= 0) i = end;
            }
            ++i;
        }

    }

private:
    struct Rule { QRegularExpression re; QTextCharFormat fmt; };
    std::vector<Rule> rules_;
    QTextCharFormat commentFmt_;
    QTextCharFormat stringFmt_, directiveFmt_;
};

ScriptEditor::ScriptEditor(ProcessHandle* proc, AutoAssembler* autoAsm, QWidget* parent)
    : QMainWindow(parent), proc_(proc), autoAsm_(autoAsm) {

    setWindowTitle("Auto Assembler");
    resize(700, 500);

    // Toolbar
    auto* toolbar = new QToolBar;
    executeBtn_ = new QAction("Execute", this);
    executeBtn_->setEnabled(proc_ && autoAsm_);
    executeBtn_->setObjectName("primaryButton");
    executeBtn_->setToolTip("Enable the script in the selected process");
    connect(executeBtn_, &QAction::triggered, this, &ScriptEditor::onExecute);

    disableBtn_ = new QAction("Disable", this);
    disableBtn_->setEnabled(false);
    connect(disableBtn_, &QAction::triggered, this, &ScriptEditor::onDisable);

    auto* checkBtn = new QAction("Syntax Check", this);
    connect(checkBtn, &QAction::triggered, this, &ScriptEditor::onCheck);

    auto* addTableBtn = new QAction("Add to Cheat Table", this);
    addTableBtn_ = addTableBtn;
    addTableBtn_->setEnabled(false);
    addTableBtn->setToolTip("Save this script as a cheat-table entry whose checkbox "
                            "enables/disables it.");
    connect(addTableBtn, &QAction::triggered, this, &ScriptEditor::onAddToTable);

    auto* loadBtn = new QAction("Load", this);
    connect(loadBtn, &QAction::triggered, this, [this]() {
        QPointer<ScriptEditor> self(this);
        auto path = QFileDialog::getOpenFileName(this, "Load Script", "", "CE Scripts (*.cea *.asm);;All Files (*)");
        if (!self || path.isEmpty()) return;
        QFile f(path);
        if (f.open(QIODevice::ReadOnly)) {
            editor_->setPlainText(QTextStream(&f).readAll());
        } else QMessageBox::warning(this, "Load failed", f.errorString());
    });

    auto* saveBtn = new QAction("Save", this);
    connect(saveBtn, &QAction::triggered, this, [this]() {
        QPointer<ScriptEditor> self(this);
        auto path = QFileDialog::getSaveFileName(this, "Save Script", "", "CE Scripts (*.cea);;All Files (*)");
        if (!self || path.isEmpty()) return;
        QSaveFile file(path);
        const QByteArray bytes = editor_->toPlainText().toUtf8();
        if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit())
            QMessageBox::warning(this, "Save failed", file.errorString());
    });

    toolbar->setMovable(false);
    toolbar->addAction(executeBtn_);
    toolbar->addAction(disableBtn_);
    toolbar->addSeparator();
    toolbar->addAction(checkBtn);
    toolbar->addAction(addTableBtn);
    toolbar->addSeparator();
    toolbar->addAction(loadBtn);
    toolbar->addAction(saveBtn);
    toolbar->addSeparator();

    toolbar->setToolButtonStyle(Qt::ToolButtonTextOnly);
    toolbar->widgetForAction(executeBtn_)->setObjectName("primaryButton");
    executeBtn_->setShortcut(QKeySequence("Ctrl+Return"));
    addAction(executeBtn_);
    loadBtn->setShortcut(QKeySequence::Open);
    addAction(loadBtn);
    saveBtn->setShortcut(QKeySequence::Save);
    addAction(saveBtn);

    // Injection templates gather a site and delegate to the live-code generator.
    auto* templateMenu = new QMenu(toolbar);

    for (const auto& t : ce::builtinAaTemplates()) {
        QString label = QString::fromStdString(t.name);
        auto* action = templateMenu->addAction(label);
        action->setToolTip(QString::fromStdString(t.description));
        if (t.injection != ce::InjectionKind::None) {
            auto kind = t.injection;
            connect(action, &QAction::triggered, this, [this, kind]() { onGenerateInjection(kind); });
            if (kind == ce::InjectionKind::Code) {
                action->setShortcut(QKeySequence("Ctrl+I"));
                addAction(action);
            }
            continue;
        }
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
    auto* templateAction = toolbar->addAction("Templates");
    templateAction->setMenu(templateMenu);
    templateAction->setToolTip("Generate a template for the selected instruction (Ctrl+I)");
    if (auto* button = qobject_cast<QToolButton*>(toolbar->widgetForAction(templateAction)))
        button->setPopupMode(QToolButton::InstantPopup);

    addToolBar(toolbar);

    // Main content: editor (top) + output (bottom)
    auto* splitter = new QSplitter(Qt::Vertical);

    editor_ = new QPlainTextEdit;
    editor_->setFont(QFont("Monospace", 10));
    editor_->setLineWrapMode(QPlainTextEdit::NoWrap);
    editor_->setTabStopDistance(QFontMetricsF(editor_->font()).horizontalAdvance(' ') * 4);
    new AaHighlighter(editor_->document());   // syntax coloring
    editor_->setPlaceholderText("Choose Templates to generate an injection at the selected instruction,\n"
                                "or write an Auto Assembler script here.");
    splitter->addWidget(editor_);

    output_ = new QTextEdit;
    output_->setReadOnly(true);
    output_->setFont(QFont("Monospace", 9));
    output_->setMaximumHeight(150);
    // The console paints its own line colors, so it can't inherit the app
    // stylesheet; give it the theme's editor background/text (was hardcoded dark,
    // which stayed dark in light mode).
    connect(qApp, &QApplication::paletteChanged, this, [this, previous = editorPalette()]() mutable {
        auto current = editorPalette();
        recolorConsole(output_->document(), previous, current);
        previous = current;
    });
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

ScriptEditor::~ScriptEditor() {
    cleanupInjection(false);
}

void ScriptEditor::closeEvent(QCloseEvent* event) {
    if (!cleanupInjection()) { event->ignore(); return; }
    QMainWindow::closeEvent(event);
}

void ScriptEditor::updateExecutionActions() {
    executeBtn_->setEnabled(proc_ && autoAsm_ && !enabled_ && !busy_);
    disableBtn_->setEnabled(proc_ && autoAsm_ && enabled_ && !busy_);
}

void ScriptEditor::onExecute() {
    if (busy_ || enabled_) return;
    if (!proc_ || !autoAsm_) {
        output_->setTextColor(ce::gui::editorPalette().error);
        output_->append("No process selected!");
        return;
    }

    AutoAsmUiOperation operation(autoAsm_);
    if (!operation) return;
    QPointer<ScriptEditor> self(this);
    busy_ = true;
    updateExecutionActions();
    auto restore = qScopeGuard([self] { if (self) { self->busy_ = false; self->updateExecutionActions(); } });
    const auto script = editor_->toPlainText().toStdString();
    auto* process = proc_;
    auto* assembler = autoAsm_;
    const auto before = beforeExecute_;
    if (before) before();
    if (!self) return;
    output_->clear();
    output_->setTextColor(ce::gui::editorPalette().text);
    output_->append("Executing...");

    auto result = assembler->execute(*process, script);
    if (!self) {
        // A deferred/forced widget deletion during a Lua callback must not drop
        // a successful result before making a cleanup attempt.
        (void)assembler->disable(*process, script, result.disableInfo);
        return;
    }

    for (auto& msg : result.log)
        output_->append(QString::fromStdString(msg));

    if (result.success) {
        output_->setTextColor(ce::gui::editorPalette().success);
        output_->append("Script executed successfully.");
        lastDisableInfo_ = result.disableInfo;
        enabledScript_ = script;
        enabled_ = true;
        enableOrder_ = AutoAsmUiOperation::nextOrder();
    } else {
        output_->setTextColor(ce::gui::editorPalette().error);
        output_->append("FAILED: " + QString::fromStdString(result.error));
        if (result.disableInfo.ownership || result.disableInfo.image || !result.disableInfo.symbols.empty() ||
            !result.disableInfo.originals.empty() || !result.disableInfo.allocs.empty() || !result.disableInfo.protections.empty()) {
            lastDisableInfo_ = std::move(result.disableInfo);
            enabledScript_ = script;
            enabled_ = true;
            enableOrder_ = AutoAsmUiOperation::nextOrder();
            output_->append("Cleanup is still pending. Use Disable to retry restoration.");
        }
    }
}

void ScriptEditor::onDisable() {
    cleanupInjection();
}

bool ScriptEditor::cleanupInjection(bool report) {
    if (busy_) return false;
    if (!enabled_) return true;
    if (!proc_ || !autoAsm_) return false;
    AutoAsmUiOperation operation(autoAsm_, AutoAsmUiOperation::Purpose::Cleanup);
    if (!operation) return false;
    QPointer<ScriptEditor> self(this);
    busy_ = true;
    updateExecutionActions();
    auto restore = qScopeGuard([self] { if (self) { self->busy_ = false; self->updateExecutionActions(); } });
    const auto script = enabledScript_;
    const auto undo = lastDisableInfo_;
    auto* process = proc_;
    auto* assembler = autoAsm_;
    const auto before = beforeExecute_;
    if (before) before();

    if (self && report) {
        output_->clear();
        output_->setTextColor(ce::gui::editorPalette().text);
        output_->append("Disabling...");
    }

    auto result = assembler->disable(*process, script, undo);
    if (!self) return result.success;
    lastDisableInfo_ = result.disableInfo;

    if (report) for (auto& msg : result.log) output_->append(QString::fromStdString(msg));

    if (result.success) {
        if (report) {
            output_->setTextColor(ce::gui::editorPalette().success);
            output_->append("Script disabled.");
        }
        enabled_ = false;
        enabledScript_.clear();
        enableOrder_ = 0;
    } else {
        if (report) {
            output_->setTextColor(ce::gui::editorPalette().error);
            output_->append("Cleanup incomplete: " + QString::fromStdString(result.error));
            output_->append("Recovery state retained. Use Disable to retry.");
        }
    }
    return result.success;
}

void ScriptEditor::onGenerateCodeInjection() {
    onGenerateInjection(ce::InjectionKind::Code);
}

void ScriptEditor::onGenerateInjection(ce::InjectionKind kind) {
    QPointer<ScriptEditor> self(this);
    if (!proc_) {
        QMessageBox::warning(this, "No process", "Attach to a process first.");
        return;
    }
    if (enabled_) {
        QMessageBox::information(this, "Injection template", "Disable the current script before generating another injection.");
        return;
    }
    QString initial;
    if (injectionAddress_) {
        initial = "0x" + QString::number(injectionAddress_, 16);
        for (const auto& m : proc_->modules()) {
            if (injectionAddress_ >= m.base && injectionAddress_ - m.base < m.size) {
                initial = QString("\"%1\"+0x%2").arg(QString::fromStdString(m.name), QString::number(injectionAddress_ - m.base, 16));
                break;
            }
        }
    }
    bool ok = false;
    QString text = QInputDialog::getText(this, "Injection template",
        "Address or expression to inject at:", QLineEdit::Normal, initial, &ok);
    if (!self || !ok || text.trimmed().isEmpty()) return;
    ce::SymbolResolver symbols;
    symbols.loadProcess(*proc_);
    auto address = ce::ExpressionParser(proc_, &symbols).parse(text.trimmed().toStdString());
    if (!address || !*address) {
        QMessageBox::warning(this, "Bad address", "Enter a valid address, module offset, or symbol expression.");
        return;
    }
    std::string pointerRegister;
    if (kind == ce::InjectionKind::Pointer) {
        QString reg = QInputDialog::getText(this, "Pointer injection", "Register holding the pointer:",
            QLineEdit::Normal, proc_->runs32BitCode() ? "eax" : "rax", &ok);
        if (!self || !ok || reg.trimmed().isEmpty()) return;
        pointerRegister = reg.trimmed().toStdString();
    }
    std::string genErr;
    size_t size = *address == injectionAddress_ ? injectionSize_ : 5;
    std::string script = ce::generateInjectionScript(*proc_, *address, kind, genErr, pointerRegister, size);
    if (script.empty()) {
        QMessageBox::warning(this, "Injection template", QString::fromStdString(genErr));
        return;
    }
    if (!editor_->toPlainText().trimmed().isEmpty()) {
        auto answer = QMessageBox::question(this, "Replace script?",
            "Replace the current script with the generated injection?",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
        if (!self || answer != QMessageBox::Yes) return;
    }
    injectionAddress_ = *address;
    injectionSize_ = size;
    editor_->setPlainText(QString::fromStdString(script));
    output_->clear();
    output_->setTextColor(ce::gui::editorPalette().success);
    output_->append(QString("Generated injection at 0x%1. Edit the code in newmem.").arg(QString::number(*address, 16)));
}

void ScriptEditor::onAddToTable() {
    QPointer<ScriptEditor> self(this);
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
    if (!self || !ok) return;
    addToTable_(desc, script);
    output_->setTextColor(ce::gui::editorPalette().success);
    output_->append("Saved to the cheat table. Toggle its checkbox to enable/disable.");
}

void ScriptEditor::onCheck() {
    if (!autoAsm_ || busy_) return;
    AutoAsmUiOperation operation(autoAsm_);
    if (!operation) return;
    QPointer<ScriptEditor> self(this);
    busy_ = true;
    auto restore = qScopeGuard([self] { if (self) { self->busy_ = false; self->updateExecutionActions(); } });
    auto script = editor_->toPlainText().toStdString();
    output_->clear();

    auto result = autoAsm_->check(script);
    if (!self) return;
    for (auto& msg : result.log)
        output_->append(QString::fromStdString(msg));

    if (result.success) {
        output_->setTextColor(ce::gui::editorPalette().success);
        output_->append("Syntax check passed.");
    }
}

} // namespace ce::gui
