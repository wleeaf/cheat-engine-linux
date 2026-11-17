#include "gui/helpmarkdown.hpp"

#include <md4c-html.h>
#include <md4c.h>

#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>
#include <QUrl>

#include <string>

namespace {

/// Value of a single attribute in the text between "<img" and ">".
QString attributeValue(const QString& attributes, const QString& name) {
    const QRegularExpression re(
        QStringLiteral(R"attr((?<![-\w])%1\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>/]+)))attr")
            .arg(QRegularExpression::escape(name)),
        QRegularExpression::CaseInsensitiveOption);
    const auto match = re.match(attributes);
    if (!match.hasMatch()) return {};
    for (int group = 1; group <= 3; ++group) {
        if (match.capturedStart(group) >= 0) return match.captured(group);
    }
    return {};
}

QString escapeAltText(QString text) {
    text.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
    text.replace(QLatin1Char('['), QStringLiteral("\\["));
    text.replace(QLatin1Char(']'), QStringLiteral("\\]"));
    return text;
}

/// One Markdown image for an <img ...> tag.
QString imageMarkdown(const QString& attributes, const QString& baseDir) {
    const QString src = attributeValue(attributes, QStringLiteral("src")).trimmed();
    QString alt = attributeValue(attributes, QStringLiteral("alt")).trimmed();
    if (alt.isEmpty()) alt = QFileInfo(src).fileName();
    alt = escapeAltText(alt);
    if (src.isEmpty()) return alt;

    const QUrl url(src);
    if (!url.scheme().isEmpty())   // http(s):, data:, ...
        return QStringLiteral("![%1](%2)").arg(alt, src);

    const QString path = QDir(baseDir).absoluteFilePath(src);
    if (QFileInfo::exists(path))
        return QStringLiteral("![%1](%2)").arg(alt, QUrl::fromLocalFile(path).toString());

    return alt;   // not shipped with this build: show the caption, not a broken image
}

void appendHtml(const MD_CHAR* text, MD_SIZE size, void* userdata) {
    static_cast<std::string*>(userdata)->append(text, size);
}

} // namespace

namespace ce::gui {

QString prepareHelpMarkdown(const QString& markdown, const QString& baseDir) {
    // Only <img> is block-level HTML in the shipped docs. A single pass
    // replaces every tag regardless of whether it starts its own block, which
    // is also correct inline.
    static const QRegularExpression imgTag(QStringLiteral(R"(<img\b[^>]*>)"),
                                           QRegularExpression::CaseInsensitiveOption);

    QString prepared;
    prepared.reserve(markdown.size());
    qsizetype copied = 0;
    auto it = imgTag.globalMatch(markdown);
    while (it.hasNext()) {
        const auto match = it.next();
        prepared += markdown.mid(copied, match.capturedStart() - copied);
        QString attributes = match.captured();
        attributes.remove(0, 4);   // "<img"
        attributes.chop(1);        // ">"
        prepared += imageMarkdown(attributes, baseDir);
        copied = match.capturedEnd();
    }
    prepared += markdown.mid(copied);
    return prepared;
}

QString helpHtmlFromMarkdown(const QString& markdown, const QString& baseDir) {
    const QByteArray utf8 = prepareHelpMarkdown(markdown, baseDir).toUtf8();
    std::string html;
    // The docs are Markdown only: raw HTML blocks are escaped, and the images
    // were converted above, so md4c never needs to pass HTML through.
    const unsigned flags = MD_DIALECT_GITHUB | MD_FLAG_TABLES | MD_FLAG_STRIKETHROUGH
                           | MD_FLAG_TASKLISTS | MD_FLAG_PERMISSIVEATXHEADERS
                           | MD_FLAG_NOHTMLBLOCKS | MD_FLAG_NOHTMLSPANS;
    if (md_html(utf8.constData(), MD_SIZE(utf8.size()), &appendHtml, &html, flags, 0) != 0)
        return {};
    return QString::fromUtf8(html.data(), qsizetype(html.size()));
}

} // namespace ce::gui
