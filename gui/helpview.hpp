#pragma once
/// Help viewer: renders the shipped Markdown docs through md4c as HTML (Qt's
/// own importer drops the blocks after a raw HTML block and styles code blocks
/// poorly) and paints a clipboard button in the corner of every code block.
/// The button copies that block, which is the one thing people want from a
/// help page full of commands.

#include <QColor>
#include <QString>
#include <QTextBrowser>
#include <QUrl>
#include <QVector>

#include <functional>

class QTimer;

namespace ce::gui {

class HelpView : public QTextBrowser {
    Q_OBJECT
public:
    explicit HelpView(QWidget* parent = nullptr);

    /// Renders `markdown`, resolving relative images against `baseDir` and
    /// relative links against `sourceUrl` (the doc's GitHub URL). Does not add
    /// a history entry (used for the initial render and by tests/screenshots).
    void setHelpMarkdown(const QString& markdown, const QString& baseDir,
                         const QUrl& sourceUrl = {});

    /// Opens a doc from disk and records it in the Back/Forward history.
    void loadDocFile(const QString& path, const QUrl& sourceUrl = {});

    /// Browser-style navigation between the docs opened in this window.
    bool canGoBack() const;
    bool canGoForward() const;
    void goBack();
    void goForward();

    /// Maps a repository-relative path ("docs/SCRIPTING.md") to a local file,
    /// or an empty string when that doc is not shipped offline. Links to docs
    /// that resolve here open in this view; other links do not open a browser
    /// (the dialog's "Open on GitHub" button is the way to the online docs).
    using DocResolver = std::function<QString(const QString& relPath)>;
    void setDocResolver(DocResolver resolver) { docResolver_ = std::move(resolver); }

    /// Handles a link the way clicking it does: shipped docs open in this
    /// view, other targets show where the document lives (no browser popup).
    /// Public so the smoke test can exercise it without synthesising clicks.
    void activateLink(const QUrl& link);

    /// Absolute URL a link in the page resolves to (for tests).
    QUrl resolveLink(const QUrl& link) const;

    /// For tests: how many copyable code blocks were found, their text, and
    /// the copy button geometry (empty when the block is not on screen).
    int codeBlockCount() const { return codeBlocks_.size(); }
    QString codeBlockText(int index) const;
    QRect codeBlockButtonRect(int index) const { return buttonRect(index); }

protected:
    void mouseReleaseEvent(QMouseEvent* event) override;
    void paintEvent(QPaintEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;

signals:
    /// Emitted whenever Back/Forward availability can change.
    void historyChanged();

private:
    struct CodeBlock {
        QVector<int> lines;   // QTextBlock numbers of the code lines
        QString text;         // the block's text, without the trailing blank line
    };

    QRect buttonRect(int index) const;
    int buttonAt(const QPoint& point) const;
    void collectCodeBlocks();
    QString styleSheet();

    struct Page {
        QString path;
        QUrl sourceUrl;
    };

    void renderPage(const Page& page);
    void renderMarkdown(const QString& markdown, const QString& baseDir, const QUrl& sourceUrl);
    void pushPage(const Page& page);

    QVector<CodeBlock> codeBlocks_;
    QColor codeBackground_;
    QUrl sourceUrl_;
    DocResolver docResolver_;
    QVector<Page> history_;
    int currentPage_ = -1;
    int hovered_ = -1;
    int copied_ = -1;
    QTimer* resetTimer_;
};

} // namespace ce::gui
