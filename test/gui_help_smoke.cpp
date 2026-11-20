// Offscreen smoke test for the Help windows.
//
// The help pages used to be rendered with QTextDocument::setMarkdown, whose
// md4c-based importer drops every block after a raw HTML block: README.md
// opens with an <img>, so the window showed only the introduction. They are
// now rendered through the vendored md4c into HTML, which also gives the pages
// GitHub-style code cards with a copy button on each block.
//
//   gui_help_smoke                  render the shipped docs and assert them
//   gui_help_smoke --shot out.png   also save README.md as a PNG for review

#include "gui/helpview.hpp"
#include "gui/theme.hpp"

#include <QApplication>
#include <QClipboard>
#include <QFile>
#include <QFileInfo>
#include <QMouseEvent>
#include <QTextDocument>
#include <QTextBlock>
#include <QUrl>

#include <cstdio>

namespace {

int failures = 0;

QString readFile(const QString& path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        std::fprintf(stderr, "FAIL: cannot read %s\n", qPrintable(path));
        ++failures;
        return {};
    }
    return QString::fromUtf8(file.readAll());
}

void expectContains(const QString& text, const QString& needle, const QString& page) {
    if (text.contains(needle)) return;
    std::fprintf(stderr, "FAIL: %s does not contain \"%s\"\n", qPrintable(page),
                 qPrintable(needle));
    ++failures;
}

} // namespace

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);
    ce::gui::applyTheme(/*dark=*/true);

    const QString root = QStringLiteral(CE_SOURCE_DIR);
    const QString readmePath = root + QStringLiteral("/README.md");
    const QString readme = readFile(readmePath);
    if (readme.isEmpty()) return 1;

    // The raw HTML block this test exists for must still be in the page.
    expectContains(readme, QStringLiteral("<img"), QStringLiteral("README.md source"));

    ce::gui::HelpView view;
    view.setDocResolver([&root](const QString& rel) {
        const QString path = root + QLatin1Char('/') + rel;
        return QFileInfo::exists(path) ? path : QString();
    });
    view.loadDocFile(readmePath, QUrl(QStringLiteral(
                         "https://github.com/wleeaf/cheat-engine-linux/blob/main/README.md")));
    view.resize(700, 900);
    view.show();
    for (int i = 0; i < 20; ++i) QApplication::processEvents();
    // Grow to the full page after the first layout, so every block is on screen.
    view.resize(700, std::min(4000, int(view.document()->size().height()) + 8));
    for (int i = 0; i < 20; ++i) QApplication::processEvents();

    // The whole page must be there, on both sides of the image.
    const QString text = view.document()->toPlainText();
    for (const char* needle : {"Cheat Engine for Linux", "Scanning:", "Debugger:",
                               "Disassembler and Auto Assembler:", ".CETRAINER",
                               "Install", "sudo apt install", "AI Assistant",
                               "Learn with the tutorials", "License"}) {
        expectContains(text, QString::fromLatin1(needle), QStringLiteral("README.md"));
    }
    // The screenshot is rendered as an image with a file: URL.
    expectContains(view.document()->toHtml(), QStringLiteral("screenshot.png"),
                   QStringLiteral("README.md render"));

    // Relative links resolve to the doc's GitHub URL instead of doing nothing.
    const QUrl benchmark = view.resolveLink(QUrl(QStringLiteral("BENCHMARK.md")));
    if (benchmark.toString() != QLatin1String(
            "https://github.com/wleeaf/cheat-engine-linux/blob/main/BENCHMARK.md")) {
        std::fprintf(stderr, "FAIL: relative link resolves to %s\n",
                     qPrintable(benchmark.toString()));
        ++failures;
    }
    const QUrl issues = view.resolveLink(QUrl(QStringLiteral("../../issues")));
    if (issues.toString() != QLatin1String(
            "https://github.com/wleeaf/cheat-engine-linux/issues")) {
        std::fprintf(stderr, "FAIL: parent-relative link resolves to %s\n",
                     qPrintable(issues.toString()));
        ++failures;
    }

    // Code blocks are reportable and their copy buttons are placed inside the
    // view; clicking one copies exactly that block.
    if (view.codeBlockCount() < 2) {
        std::fprintf(stderr, "FAIL: expected at least two code blocks, found %d\n",
                     view.codeBlockCount());
        ++failures;
    } else {
        const QString first = view.codeBlockText(0);
        expectContains(first, QStringLiteral("sudo apt install"), QStringLiteral("code block"));
        const QRect button = view.codeBlockButtonRect(0);
        if (!button.isValid() || !view.viewport()->rect().contains(button.center())) {
            std::fprintf(stderr,
                         "FAIL: first copy button is not on screen (button %d,%d %dx%d, viewport %dx%d)\n",
                         button.x(), button.y(), button.width(), button.height(),
                         view.viewport()->width(), view.viewport()->height());
            ++failures;
        } else {
            QMouseEvent press(QEvent::MouseButtonPress, QPointF(button.center()), QPointF(button.center()),
                              Qt::LeftButton, Qt::LeftButton, Qt::NoModifier);
            QApplication::sendEvent(view.viewport(), &press);
            QApplication::processEvents();
            if (QGuiApplication::clipboard()->text() != first) {
                std::fprintf(stderr, "FAIL: clicking the copy button did not copy the block\n");
                ++failures;
            }
        }
    }

    // Links to shipped docs open inside the view; links to docs that are not
    // shipped keep the current page instead of going blank or starting a
    // browser (the dialog's "Open on GitHub" button is the online way).
    view.activateLink(QUrl(QStringLiteral("docs/SCRIPTING.md")));
    for (int i = 0; i < 10; ++i) QApplication::processEvents();
    expectContains(view.document()->toPlainText(), QStringLiteral("Typed memory access"),
                   QStringLiteral("in-app navigation"));
    view.activateLink(QUrl(QStringLiteral("docs/NOT_SHIPPED.md")));
    for (int i = 0; i < 10; ++i) QApplication::processEvents();
    expectContains(view.document()->toPlainText(), QStringLiteral("Typed memory access"),
                   QStringLiteral("missing doc keeps the page"));

    // Back/Forward walk the opened docs and never lose the page.
    if (!view.canGoBack() || view.canGoForward()) {
        std::fprintf(stderr, "FAIL: history state after navigation is wrong\n");
        ++failures;
    }
    view.goBack();
    expectContains(view.document()->toPlainText(), QStringLiteral("Scanning:"),
                   QStringLiteral("Back to README"));
    if (!view.canGoForward()) {
        std::fprintf(stderr, "FAIL: Forward is not available after Back\n");
        ++failures;
    }
    view.goForward();
    expectContains(view.document()->toPlainText(), QStringLiteral("Typed memory access"),
                   QStringLiteral("Forward to SCRIPTING"));

    // The Lua documentation goes through the same renderer.
    const QString scriptingPath = root + QStringLiteral("/docs/SCRIPTING.md");
    const QString scripting = readFile(scriptingPath);
    if (scripting.isEmpty()) return 1;
    ce::gui::HelpView scriptingView;
    scriptingView.setHelpMarkdown(scripting, QFileInfo(scriptingPath).absolutePath());
    const QString scriptingText = scriptingView.document()->toPlainText();
    for (const char* needle : {"Typed memory access", "getIl2CppClassLayout", "cescan lua"}) {
        expectContains(scriptingText, QString::fromLatin1(needle),
                       QStringLiteral("docs/SCRIPTING.md"));
    }
    if (scriptingView.codeBlockCount() == 0) {
        std::fprintf(stderr, "FAIL: no code blocks found in docs/SCRIPTING.md\n");
        ++failures;
    }

    // UI review aid, not part of the CI assertion. An optional "light"
    // argument renders the light theme instead of the default dark one.
    if (argc > 2 && QString::fromLocal8Bit(argv[1]) == QLatin1String("--shot")) {
        const bool light = argc > 3 && QString::fromLocal8Bit(argv[3]) == QLatin1String("light");
        ce::gui::applyTheme(!light);
        ce::gui::HelpView shot;
        shot.setHelpMarkdown(readme, QFileInfo(readmePath).absolutePath());
        shot.document()->setTextWidth(660);
        shot.resize(700, std::min(4000, int(shot.document()->size().height()) + 8));
        shot.show();
        for (int i = 0; i < 30; ++i) QApplication::processEvents();
        const QString out = QString::fromLocal8Bit(argv[2]);
        if (!shot.grab().save(out)) {
            std::fprintf(stderr, "FAIL: cannot save %s\n", qPrintable(out));
            ++failures;
        } else {
            std::printf("gui_help_smoke: help page saved to %s\n", qPrintable(out));
        }
    }

    if (failures) {
        std::fprintf(stderr, "gui_help_smoke: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("gui_help_smoke: OK (README.md %lld chars, %d code blocks; docs/SCRIPTING.md %lld chars, %d code blocks)\n",
                static_cast<long long>(text.size()), view.codeBlockCount(),
                static_cast<long long>(scriptingText.size()), scriptingView.codeBlockCount());
    return 0;
}
