#include "gui/helpview.hpp"

#include "gui/helpmarkdown.hpp"
#include "gui/theme.hpp"

#include <QApplication>
#include <QClipboard>
#include <QMouseEvent>
#include <QPainter>
#include <QScrollBar>
#include <QTextBlock>
#include <QTextBlockFormat>
#include <QCursor>
#include <QFile>
#include <QFileInfo>
#include <QTextCursor>
#include <QTimer>
#include <QToolTip>

#include <algorithm>

namespace ce::gui {

HelpView::HelpView(QWidget* parent) : QTextBrowser(parent) {
    // Links are handled by setSource(): they open shipped docs in this view and
    // never start a browser (the dialog's "Open on GitHub" button does that).
    setOpenExternalLinks(false);
    setFrameShape(QFrame::NoFrame);
    document()->setDocumentMargin(16);

    resetTimer_ = new QTimer(this);
    resetTimer_->setSingleShot(true);
    resetTimer_->setInterval(1400);
    connect(resetTimer_, &QTimer::timeout, this, [this] {
        copied_ = -1;
        viewport()->update();
    });
    // The buttons are painted in viewport coordinates, so they follow scrolling.
    connect(verticalScrollBar(), &QScrollBar::valueChanged, this, [this] { viewport()->update(); });
}

QString HelpView::styleSheet() {
    // GitHub's Markdown design (github-markdown-css): dark or light canvas,
    // muted code surface, default border, accent links, muted quotes. Qt's rich
    // text supports the typographic part of that CSS; the parts it cannot do
    // (rounded corners, shadows) are left out rather than approximated badly.
    const bool dark = isDarkTheme();
    const QColor text = dark ? QColor("#e6edf3") : QColor("#1f2328");
    const QColor page = dark ? QColor("#0d1117") : QColor("#ffffff");
    const QColor link = dark ? QColor("#2f81f7") : QColor("#0969da");
    const QColor dim = dark ? QColor("#848d97") : QColor("#59636e");
    const QColor border = dark ? QColor("#30363d") : QColor("#d0d7de");
    codeBackground_ = dark ? QColor("#161b22") : QColor("#f6f8fa");
    setPalette([&] {
        QPalette p = palette();
        p.setColor(QPalette::Text, text);
        p.setColor(QPalette::Base, page);
        p.setColor(QPalette::Window, page);
        p.setColor(QPalette::Link, link);
        p.setColor(QPalette::PlaceholderText, dim);
        return p;
    }());
    viewport()->setStyleSheet(QStringLiteral("background-color: %1;").arg(page.name()));
    setStyleSheet(QStringLiteral("QTextBrowser { background-color: %1; }").arg(page.name()));
    // GitHub's sizes relative to a 16px body: h1 2em, h2 1.5em, h3 1.25em,
    // code 85%. Point sizes keep the page consistent with the interface font.
    const qreal base = std::max(9.0, QApplication::font().pointSizeF());
    const auto size = [base](qreal em) {
        return QString::number(std::max(7.0, base * em), 'f', 1);
    };
    return QStringLiteral(R"CSS(
        body { color: %1; background-color: %2; font-size: %3pt; }
        h1 { font-size: %4pt; font-weight: 700; margin-top: 0px; margin-bottom: 12px;
             border-bottom: 1px solid %12; padding-bottom: 6px; }
        h2 { font-size: %5pt; font-weight: 700; margin-top: 20px; margin-bottom: 10px;
             border-bottom: 1px solid %12; padding-bottom: 4px; }
        h3 { font-size: %6pt; font-weight: 700; margin-top: 16px; margin-bottom: 8px; }
        h4 { font-size: %7pt; font-weight: 700; margin-top: 14px; margin-bottom: 6px; }
        p { margin-top: 6px; margin-bottom: 10px; }
        a { color: %8; text-decoration: none; }
        pre { background-color: %9; color: %1; font-family: 'monospace';
              font-size: %10pt; margin-top: 0px; margin-bottom: 0px; }
        code { background-color: %9; color: %1; font-family: 'monospace'; font-size: %10pt; }
        blockquote { color: %11; margin-left: 22px; margin-right: 22px;
                     margin-top: 0px; margin-bottom: 10px; }
        li { margin-top: 2px; margin-bottom: 2px; }
        hr { color: %12; }
        table { border: 1px solid %12; }
        th, td { border: 1px solid %12; padding: 6px; }
    )CSS")
        .arg(text.name(), page.name(), size(1.0), size(2.0), size(1.5), size(1.25),
             size(1.0), link.name(), codeBackground_.name(), size(0.85), dim.name(),
             border.name());
}

QUrl HelpView::resolveLink(const QUrl& link) const {
    if (link.isRelative() && !sourceUrl_.isEmpty()) return sourceUrl_.resolved(link);
    return link;
}

namespace {
constexpr char kGithubBlobPrefix[] =
    "https://github.com/wleeaf/cheat-engine-linux/blob/main/";

/// Repository-relative path for a docs link, or an empty string for a link
/// that points outside the repository docs.
QString repoRelativePath(const QUrl& url) {
    const QString prefix = QString::fromLatin1(kGithubBlobPrefix);
    QString path = url.toString(QUrl::RemoveFragment);
    if (!path.startsWith(prefix)) return {};
    const QString rel = path.mid(prefix.size());
    return rel.isEmpty() || rel.contains(QLatin1String("..")) ? QString() : rel;
}
} // namespace

void HelpView::activateLink(const QUrl& link) {
    const QUrl resolved = resolveLink(link);
    const QString rel = repoRelativePath(resolved);
    if (!rel.isEmpty() && docResolver_) {
        const QString local = docResolver_(rel);
        if (!local.isEmpty() && QFileInfo::exists(local)) {
            loadDocFile(local, QUrl(QString::fromLatin1(kGithubBlobPrefix) + rel));
            return;
        }
    }
    // Not shipped offline: keep the current page and say where the document is.
    QToolTip::showText(QCursor::pos(),
                       tr("This page is not part of the offline help. Use \"Open on GitHub\" to read it online."),
                       this);
}

void HelpView::mouseReleaseEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        const QString href = anchorAt(event->position().toPoint());
        if (!href.isEmpty()) {
            // Handle it ourselves: QTextBrowser would navigate to the (often
            // missing) local target and leave the window blank.
            activateLink(QUrl(href));
            event->accept();
            return;
        }
    }
    QTextBrowser::mouseReleaseEvent(event);
}

void HelpView::setHelpMarkdown(const QString& markdown, const QString& baseDir,
                               const QUrl& sourceUrl) {
    renderMarkdown(markdown, baseDir, sourceUrl);
}

void HelpView::renderMarkdown(const QString& markdown, const QString& baseDir,
                              const QUrl& sourceUrl) {
    sourceUrl_ = sourceUrl;
    Q_UNUSED(baseDir)
    document()->setDefaultStyleSheet(styleSheet());
    setHtml(QStringLiteral("<html><body>%1</body></html>")
                .arg(helpHtmlFromMarkdown(markdown, baseDir)));
    collectCodeBlocks();
    verticalScrollBar()->setValue(0);
}

void HelpView::loadDocFile(const QString& path, const QUrl& sourceUrl) {
    pushPage(Page{path, sourceUrl});
    renderPage(history_.at(currentPage_));
}

void HelpView::pushPage(const Page& page) {
    while (history_.size() > currentPage_ + 1) history_.removeLast();
    history_.push_back(page);
    currentPage_ = history_.size() - 1;
    emit historyChanged();
}

void HelpView::renderPage(const Page& page) {
    QFile file(page.path);
    if (!file.open(QIODevice::ReadOnly)) return;
    renderMarkdown(QString::fromUtf8(file.readAll()), QFileInfo(page.path).absolutePath(),
                   page.sourceUrl);
}

bool HelpView::canGoBack() const { return currentPage_ > 0; }
bool HelpView::canGoForward() const { return currentPage_ + 1 < history_.size(); }

void HelpView::goBack() {
    if (!canGoBack()) return;
    --currentPage_;
    renderPage(history_.at(currentPage_));
    emit historyChanged();
}

void HelpView::goForward() {
    if (!canGoForward()) return;
    ++currentPage_;
    renderPage(history_.at(currentPage_));
    emit historyChanged();
}

QString HelpView::codeBlockText(int index) const {
    if (index < 0 || index >= codeBlocks_.size()) return {};
    return codeBlocks_.at(index).text;
}

void HelpView::collectCodeBlocks() {
    codeBlocks_.clear();
    CodeBlock current;
    bool inCode = false;
    for (QTextBlock block = document()->begin(); block.isValid(); block = block.next()) {
        const QTextBlockFormat format = block.blockFormat();
        const bool code = format.background().style() != Qt::NoBrush
                          && format.background().color() == codeBackground_;
        if (code) {
            inCode = true;
            current.lines.push_back(block.blockNumber());
            if (!block.text().isEmpty()) {
                if (!current.text.isEmpty()) current.text += QLatin1Char('\n');
                current.text += block.text();
            }
        } else if (inCode) {
            inCode = false;
            if (!current.text.isEmpty()) codeBlocks_.push_back(current);
            current = CodeBlock{};
        }
    }
    if (inCode && !current.text.isEmpty()) codeBlocks_.push_back(current);
}

QRect HelpView::buttonRect(int index) const {
    if (index < 0 || index >= codeBlocks_.size()) return {};
    const CodeBlock& code = codeBlocks_.at(index);
    const QTextBlock first = document()->findBlockByNumber(code.lines.first());
    const QTextBlock last = document()->findBlockByNumber(code.lines.last());
    if (!first.isValid() || !last.isValid()) return {};
    const QRect firstRect = cursorRect(QTextCursor(first));
    const QRect lastRect = cursorRect(QTextCursor(last));
    // No button while the whole block is above or below the viewport.
    if (lastRect.bottom() < 0 || firstRect.top() > viewport()->height()) return {};
    // A long block scrolled partly out of view keeps its button at the top edge.
    const int top = std::clamp(firstRect.top(), 3, std::max(3, viewport()->height() - 26));
    const int width = 26;
    return QRect(viewport()->width() - width - 20, top + 3, width, 22);
}

int HelpView::buttonAt(const QPoint& point) const {
    for (int i = 0; i < codeBlocks_.size(); ++i) {
        const QRect rect = buttonRect(i);
        if (!rect.isEmpty() && rect.contains(point)) return i;
    }
    return -1;
}

void HelpView::paintEvent(QPaintEvent* event) {
    QTextBrowser::paintEvent(event);
    if (codeBlocks_.isEmpty()) return;
    QPainter painter(viewport());
    painter.setRenderHint(QPainter::Antialiasing);
    for (int i = 0; i < codeBlocks_.size(); ++i) {
        const QRect rect = buttonRect(i);
        if (rect.isEmpty() || !viewport()->rect().intersects(rect)) continue;
        const bool active = i == hovered_ || i == copied_;
        QColor background = active ? palette().color(QPalette::Highlight)
                                   : palette().color(QPalette::Button);
        QColor border = active ? palette().color(QPalette::Highlight)
                               : palette().color(QPalette::Mid);
        painter.setPen(border);
        painter.setBrush(background);
        painter.drawRoundedRect(rect, 5, 5);

        const QColor ink = active ? palette().color(QPalette::HighlightedText)
                                  : palette().color(QPalette::ButtonText);
        painter.setPen(QPen(ink, 1.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        const QRect icon = rect.adjusted(0, 0, 0, 0);
        if (i == copied_) {
            // A check mark while the "copied" state lasts.
            painter.drawLine(QPointF(icon.center().x() - 5, icon.center().y()),
                             QPointF(icon.center().x() - 1, icon.center().y() + 4));
            painter.drawLine(QPointF(icon.center().x() - 1, icon.center().y() + 4),
                             QPointF(icon.center().x() + 6, icon.center().y() - 4));
        } else {
            // A small clipboard: body plus the clip on top.
            const QRectF body(icon.center().x() - 6, icon.center().y() - 5, 12, 13);
            painter.drawRoundedRect(body, 2, 2);
            painter.drawLine(QPointF(icon.center().x() - 3, icon.center().y() - 7),
                             QPointF(icon.center().x() + 3, icon.center().y() - 7));
        }
    }
}

void HelpView::mouseMoveEvent(QMouseEvent* event) {
    const int hit = buttonAt(event->position().toPoint());
    if (hit != hovered_) {
        hovered_ = hit;
        viewport()->setCursor(hit >= 0 ? Qt::PointingHandCursor : Qt::IBeamCursor);
        viewport()->update();
    }
    QTextBrowser::mouseMoveEvent(event);
}

void HelpView::mousePressEvent(QMouseEvent* event) {
    const int hit = buttonAt(event->position().toPoint());
    if (hit >= 0 && event->button() == Qt::LeftButton) {
        QGuiApplication::clipboard()->setText(codeBlocks_.at(hit).text);
        copied_ = hit;
        viewport()->update();
        resetTimer_->start();
        event->accept();
        return;
    }
    QTextBrowser::mousePressEvent(event);
}

void HelpView::resizeEvent(QResizeEvent* event) {
    QTextBrowser::resizeEvent(event);
    viewport()->update();
}

} // namespace ce::gui
