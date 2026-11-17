#pragma once
/// Markdown rendering for the Help windows. Qt's own Markdown importer is
/// md4c-based but drops every block after a raw HTML block (README.md opens
/// with an <img>) and gives code blocks no styling. The docs are therefore
/// parsed with the vendored md4c and handed to QTextBrowser as HTML, which
/// also allows the GitHub-style code cards and their copy buttons.

#include <QString>

namespace ce::gui {

/// Converts the block-level HTML the shipped docs use to Markdown: an <img>
/// becomes a Markdown image with an absolute file: URL when it ships next to
/// the doc (`baseDir` is the doc's directory), or its alt text when it does
/// not. Everything else is passed through unchanged.
QString prepareHelpMarkdown(const QString& markdown, const QString& baseDir);

/// Renders the Markdown to an HTML fragment for QTextBrowser (md4c, GitHub
/// dialect, raw HTML escaped: the docs are Markdown, not HTML).
QString helpHtmlFromMarkdown(const QString& markdown, const QString& baseDir);

} // namespace ce::gui
