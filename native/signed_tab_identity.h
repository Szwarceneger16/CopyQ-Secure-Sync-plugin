// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "device_trust_journal.h"
#include <QCryptographicHash>
#include <QtEndian>

namespace cqs::native {
inline QByteArray signedTabMarkerIdentity(const trust::JoinActivation &proof) {
    const auto integer = [](quint64 value) {
        const auto encoded = qToBigEndian(value);
        return QByteArray(reinterpret_cast<const char *>(&encoded), sizeof(encoded));
    };
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(QByteArrayView("CopyQ-Secure-Sync-signed-tab-marker-v1"));
    const auto text = [&hash, &integer](const std::string &value) {
        hash.addData(integer(value.size()));
        hash.addData(QByteArrayView(value.data(), qsizetype(value.size())));
    };
    const auto token = [&hash](const trust::Token &value) {
        hash.addData(QByteArrayView(reinterpret_cast<const char *>(value.data()), value.size()));
    };
    text(proof.profileBinding);
    token(proof.group);
    token(proof.root);
    token(proof.head);
    token(proof.member);
    token(proof.tipDigest);
    hash.addData(integer(proof.generation));
    text(proof.tipId);
    return hash.result();
}

} // namespace cqs::native
