// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_join_dialog.h"
#include <QByteArray>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QFormLayout>
#include <QKeyEvent>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPointer>
#include <QPushButton>
#include <QScopeGuard>
#include <QScrollArea>
#include <QTimeZone>
#include <QVBoxLayout>
#include <limits>
#include <set>
#include <utility>

namespace cqs::native {
namespace {
constexpr qsizetype HexSize = 2 * trust::Token{}.size();
constexpr qsizetype GroupSize = 8;
constexpr qsizetype GroupedSize = HexSize + HexSize / GroupSize - 1;

QString displayToken(const trust::Token &token) {
    constexpr char digits[] = "0123456789abcdef";
    QString text;
    text.reserve(GroupedSize);
    for (std::size_t i = 0; i < token.size(); ++i) {
        if (i && (2 * i) % GroupSize == 0) text += QLatin1Char('-');
        text += QLatin1Char(digits[token[i] >> 4]);
        text += QLatin1Char(digits[token[i] & 15]);
    }
    return text;
}

int hexDigit(QChar character) {
    const auto value = character.unicode();
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

std::optional<trust::Token> parseToken(const QString &input) {
    const bool grouped = input.size() == GroupedSize;
    if (!grouped && input.size() != HexSize) return std::nullopt;

    trust::Token token{};
    qsizetype offset = 0;
    for (qsizetype digit = 0; digit < HexSize; ++digit) {
        if (grouped && digit && digit % GroupSize == 0 && input[offset++] != QLatin1Char('-'))
            return std::nullopt;
        const auto nibble = hexDigit(input[offset++]);
        if (nibble < 0) return std::nullopt;
        const auto shift = digit % 2 ? 0 : 4;
        token[static_cast<std::size_t>(digit / 2)] |= static_cast<std::uint8_t>(nibble << shift);
    }
    return token;
}

bool validReview(const trust::JoinReview &review) {
    if (review.approvers.empty() || review.approvers.size() > trust::MaxMembers) return false;
    std::set<trust::Token> ids;
    for (const auto &peer : review.approvers)
        if (!ids.insert(peer.member.id).second) return false;
    return true;
}

QLabel *textLabel(const QString &text, QWidget *parent) {
    auto *label = new QLabel(text, parent);
    label->setTextFormat(Qt::PlainText);
    label->setTextInteractionFlags(Qt::NoTextInteraction);
    return label;
}

QLabel *tokenLabel(const trust::Token &token, QWidget *parent) {
    auto *label = textLabel(displayToken(token), parent);
    label->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    return label;
}

QString expiryLabel(std::uint64_t expiry) {
    // QDateTime stores signed milliseconds internally.
    if (expiry <= static_cast<std::uint64_t>(std::numeric_limits<qint64>::max() / 1000)) {
        const auto utc = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(expiry), QTimeZone(QByteArrayLiteral("UTC")));
        const auto iso = utc.toString(Qt::ISODate);
        if (!iso.isEmpty()) return iso;
    }
    return QString::number(static_cast<qulonglong>(expiry)) + QStringLiteral(" (Unix time)");
}

class ComparisonInput final : public QLineEdit {
public:
    explicit ComparisonInput(QWidget *parent) : QLineEdit(parent) {
        // Keep one extra character so a too-long value cannot become valid by truncation.
        setMaxLength(static_cast<int>(GroupedSize + 1));
        setContextMenuPolicy(Qt::NoContextMenu);
        setAcceptDrops(false);
        setDragEnabled(false);
        setInputMethodHints(Qt::ImhNoPredictiveText | Qt::ImhLatinOnly);
    }

protected:
    bool event(QEvent *event) override {
        if (event->type() == QEvent::ShortcutOverride && clipboardShortcut(*static_cast<QKeyEvent *>(event))) {
            event->accept();
            return true;
        }
        return QLineEdit::event(event);
    }

    void keyPressEvent(QKeyEvent *event) override {
        if (clipboardShortcut(*event)) {
            event->accept();
            return;
        }
        QLineEdit::keyPressEvent(event);
    }

    void mousePressEvent(QMouseEvent *event) override {
        if (event->button() == Qt::MiddleButton) {
            event->accept();
            return;
        }
        QLineEdit::mousePressEvent(event);
    }

    void mouseReleaseEvent(QMouseEvent *event) override {
        if (event->button() == Qt::MiddleButton) {
            event->accept();
            return;
        }
        QLineEdit::mouseReleaseEvent(event);
    }

private:
    static bool clipboardShortcut(const QKeyEvent &event) {
        return event.matches(QKeySequence::Copy) || event.matches(QKeySequence::Cut) ||
               event.matches(QKeySequence::Paste);
    }
};

std::vector<ComparisonInput *> buildReview(QDialog &dialog, const trust::JoinReview &review,
                                           bool confirm, QVBoxLayout &layout) {
    dialog.setObjectName(QStringLiteral("cqsDeviceJoinReview"));
    dialog.setWindowTitle(QStringLiteral("Verify device enrollment"));
    auto *description = textLabel(QStringLiteral(
        "Enrollment grants access to synchronized clipboard history under the current group key. "
        "Compare every digit on both trusted device screens or through an independent authenticated channel."),
        &dialog);
    description->setWordWrap(true);
    layout.addWidget(description);
    if (confirm) {
        auto *instruction = textLabel(QStringLiteral(
            "Enter the full value from the other device for each approver. "
            "Use all 64 hexadecimal digits with or without the displayed separators."), &dialog);
        instruction->setWordWrap(true);
        layout.addWidget(instruction);
    }

    auto *scroll = new QScrollArea(&dialog);
    auto *body = new QWidget(scroll);
    auto *form = new QFormLayout(body);
    form->addRow(QStringLiteral("Group"), tokenLabel(review.group, body));
    form->addRow(QStringLiteral("Genesis root"), tokenLabel(review.root, body));
    form->addRow(QStringLiteral("Applicant"), tokenLabel(review.applicant.id, body));
    form->addRow(QStringLiteral("Expires"), textLabel(expiryLabel(review.expires), body));

    std::vector<ComparisonInput *> inputs;
    for (const auto &peer : review.approvers) {
        form->addRow(QStringLiteral("Approver"), tokenLabel(peer.member.id, body));
        form->addRow(QStringLiteral("Local comparison"), tokenLabel(peer.digest, body));
        if (confirm) {
            auto *input = new ComparisonInput(body);
            input->setObjectName(QStringLiteral("cqsJoinPeerValue_%1").arg(static_cast<qulonglong>(inputs.size())));
            input->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
            form->addRow(QStringLiteral("Other device's value"), input);
            inputs.push_back(input);
        }
    }
    scroll->setWidget(body);
    scroll->setWidgetResizable(true);
    layout.addWidget(scroll);
    dialog.resize(720, 480);
    return inputs;
}
std::optional<std::vector<trust::JoinConfirmation>> runReview(
    QWidget *parent, const trust::JoinReview &review, bool confirm) {
    if (!validReview(review)) return std::nullopt;
    const auto snapshot = review;
    QPointer<QDialog> dialog{new QDialog(parent)};
    // The dialog's parent can be closed while the modal event loop is active.
    const auto cleanup = qScopeGuard([&dialog] { delete dialog.data(); });
    auto *layout = new QVBoxLayout(dialog.data());
    const auto inputs = buildReview(*dialog, snapshot, confirm, *layout);
    auto *buttons = new QDialogButtonBox(confirm ? QDialogButtonBox::Ok | QDialogButtonBox::Cancel
                                                : QDialogButtonBox::StandardButtons(QDialogButtonBox::Close),
                                         dialog.data());
    QObject::connect(buttons, &QDialogButtonBox::rejected, dialog.data(), &QDialog::reject);
    if (!confirm) {
        layout->addWidget(buttons);
        (void)dialog->exec();
        return std::nullopt;
    }

    auto *error = textLabel({}, dialog.data());
    error->setObjectName(QStringLiteral("cqsJoinReviewError"));
    error->setWordWrap(true);
    layout->addWidget(error);
    buttons->button(QDialogButtonBox::Ok)->setText(QStringLiteral("Confirm comparisons"));
    layout->addWidget(buttons);

    std::optional<std::vector<trust::JoinConfirmation>> confirmed;
    QObject::connect(buttons, &QDialogButtonBox::accepted, dialog.data(), [&] {
        std::vector<trust::JoinConfirmation> entered;
        entered.reserve(inputs.size());
        for (std::size_t i = 0; i < inputs.size(); ++i) {
            const auto value = parseToken(inputs[i]->text());
            const auto &peer = snapshot.approvers[i];
            if (!value || *value != peer.digest) {
                error->setText(QStringLiteral("Check the full value against the other device and try again."));
                inputs[i]->setFocus();
                return;
            }
            entered.push_back({peer.member.id, *value});
        }
        confirmed = std::move(entered);
        dialog->accept();
    });
    if (dialog->exec() != QDialog::Accepted || !dialog) return std::nullopt;
    return confirmed;
}
} // namespace

void showDeviceJoinReview(QWidget *parent, const trust::JoinReview &review) {
    (void)runReview(parent, review, false);
}

std::optional<std::vector<trust::JoinConfirmation>>
confirmDeviceJoinReview(QWidget *parent, const trust::JoinReview &review) {
    return runReview(parent, review, true);
}
} // namespace cqs::native
