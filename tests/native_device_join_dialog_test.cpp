// SPDX-License-Identifier: GPL-3.0-or-later
#include "device_join_dialog.h"
#include "test_check.h"
#include <QApplication>
#include <QByteArray>
#include <QDialog>
#include <QDialogButtonBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTimer>
#include <iostream>

using namespace cqs;

namespace {
QString raw(const trust::Token &token) {
    return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(token.data()),
                                          static_cast<qsizetype>(token.size())).toHex());
}

QString grouped(const trust::Token &token) {
    const auto text = raw(token);
    QString result;
    for (qsizetype i = 0; i < text.size(); i += 8) {
        if (i) result += QLatin1Char('-');
        result += text.mid(i, 8);
    }
    return result;
}

QDialog &activeReview() {
    auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
    CHECK(dialog && dialog->objectName() == QStringLiteral("cqsDeviceJoinReview"));
    return *dialog;
}

QPushButton &button(QDialog &dialog, QDialogButtonBox::StandardButton id) {
    auto *buttons = dialog.findChild<QDialogButtonBox *>();
    CHECK(buttons && buttons->button(id));
    return *buttons->button(id);
}
} // namespace

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    trust::JoinReview review;
    review.group.fill(0x13);
    review.root.fill(0x2a);
    review.applicant.id.fill(0x3b);
    review.expires = 2'000'000'000;
    review.approvers.resize(2);
    review.approvers[0].member.id.fill(0x49);
    review.approvers[0].digest.fill(0xa7);
    review.approvers[1].member.id.fill(0x54);
    review.approvers[1].digest.fill(0xb6);

    QTimer::singleShot(0, [&] {
        auto &dialog = activeReview();
        CHECK(dialog.findChildren<QLineEdit *>().isEmpty());
        bool displayedFirst = false;
        bool displayedSecond = false;
        for (const auto *label : dialog.findChildren<QLabel *>()) {
            const bool first = label->text() == grouped(review.approvers[0].digest);
            const bool second = label->text() == grouped(review.approvers[1].digest);
            if (first || second) CHECK(label->textInteractionFlags() == Qt::NoTextInteraction);
            displayedFirst |= first;
            displayedSecond |= second;
        }
        CHECK(displayedFirst && displayedSecond);
        button(dialog, QDialogButtonBox::Close).click();
    });
    native::showDeviceJoinReview(nullptr, review);

    QTimer::singleShot(0, [&] {
        auto &dialog = activeReview();
        auto *first = dialog.findChild<QLineEdit *>(QStringLiteral("cqsJoinPeerValue_0"));
        auto *second = dialog.findChild<QLineEdit *>(QStringLiteral("cqsJoinPeerValue_1"));
        auto *error = dialog.findChild<QLabel *>(QStringLiteral("cqsJoinReviewError"));
        CHECK(first && second && error);
        CHECK(!first->acceptDrops() && first->contextMenuPolicy() == Qt::NoContextMenu);
        auto &confirm = button(dialog, QDialogButtonBox::Ok);
        second->setText(raw(review.approvers[1].digest).toUpper());
        first->setText(raw(review.approvers[0].digest).left(63));
        confirm.click();
        CHECK(dialog.isVisible() && !error->text().isEmpty());
        first->setText(grouped(review.approvers[0].digest) + QStringLiteral("extra"));
        confirm.click();
        CHECK(dialog.isVisible());
        first->setText(grouped(review.approvers[0].digest));
        second->setText(raw(review.approvers[0].digest));
        confirm.click();
        CHECK(dialog.isVisible());
        second->setText(raw(review.approvers[1].digest).toUpper());
        confirm.click();
    });
    const auto confirmed = native::confirmDeviceJoinReview(nullptr, review);
    CHECK(confirmed && confirmed->size() == review.approvers.size());
    for (std::size_t i = 0; i < confirmed->size(); ++i) {
        CHECK((*confirmed)[i].approver == review.approvers[i].member.id);
        CHECK((*confirmed)[i].digest == review.approvers[i].digest);
    }

    QTimer::singleShot(0, [] {
        auto &dialog = activeReview();
        button(dialog, QDialogButtonBox::Cancel).click();
    });
    CHECK(!native::confirmDeviceJoinReview(nullptr, review));
    QTimer::singleShot(0, [] { activeReview().accept(); });
    CHECK(!native::confirmDeviceJoinReview(nullptr, review));
    auto *parent = new QWidget;
    QTimer::singleShot(0, [parent] { delete parent; });
    CHECK(!native::confirmDeviceJoinReview(parent, review));
    review.approvers[1].member.id = review.approvers[0].member.id;
    CHECK(!native::confirmDeviceJoinReview(nullptr, review));
    std::cout << "Native device Join dialog checks passed\n";
}
