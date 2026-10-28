// SPDX-License-Identifier: GPL-3.0-or-later
#include "native_blob.h"
#include "packed_items.h"
#include "common/contenttype.h"
#include <QDataStream>
#include <QBuffer>
#include <QDir>
#include <QCryptographicHash>
#include <QRegularExpression>
#include <QVariant>
namespace cqs::native {
namespace {
[[noreturn]] void fail(){throw packed::Error();}
struct Secret {QByteArray bytes;~Secret(){bytes.fill(0);}};
// Bound the host's metatype serialization before accepting any allocation.
class BoundedStream final:public QIODevice {
public:
    Secret data;BoundedStream(){open(WriteOnly);}
    qint64 readData(char *,qint64) override{return -1;}
    qint64 writeData(const char *s,qint64 n) override{if(n<0||n>16384-data.bytes.size())return -1;data.bytes.append(s,n);return n;}
};
QByteArray materialize(const QVariant &value,const QString &root,std::size_t budget){
    if(value.metaType().id()==QMetaType::QByteArray){auto b=value.toByteArray();if(std::size_t(b.size())>budget)fail();return b;}
    const auto type=QMetaType::fromName("DataFile");
    if(!type.isValid()||value.metaType()!=type||!type.hasRegisteredDataStreamOperators())fail();
    BoundedStream encoded;QDataStream out(&encoded);out.setVersion(QDataStream::Qt_4_7);
    if(!type.save(out,value.constData())||out.status()!=QDataStream::Ok)fail();
    QDataStream in(encoded.data.bytes);in.setVersion(QDataStream::Qt_4_7);
    QString file;in>>file;const auto tailAt=in.device()->pos();quint8 hasKey=2;in>>hasKey;
    if(in.status()!=QDataStream::Ok||hasKey>1||file.size()>4096)fail();
    if(hasKey){quint32 size=0;in>>size;if(size!=32||in.device()->bytesAvailable()!=32)fail();in.skipRawData(32);}
    if(in.status()!=QDataStream::Ok||!in.atEnd())fail();
    const auto dataRoot=QDir::cleanPath(QDir::fromNativeSeparators(root));
    if(!QDir::isAbsolutePath(dataRoot)||root.contains(QChar(0)))fail();
    const auto relative=QDir(dataRoot).relativeFilePath(file);
    if(!QRegularExpression("^[0-9a-f]{16}/[0-9a-f]{16}/[0-9a-f]{16}/[0-9a-f]{16}\\.dat$").match(relative).hasMatch()||QDir(dataRoot).filePath(relative)!=file)fail();
    const auto bytes=readNativeBlob(file,budget+(hasKey?256:0));
    QCryptographicHash hash(QCryptographicHash::Sha256);hash.addData(QByteArrayLiteral("copyq_salt"));hash.addData(bytes);
    auto expected=relative;expected.remove('/');expected.chop(4);
    if(hash.result().toHex()!=expected.toLatin1())fail();
    if(!hasKey)return bytes;
    return withFrozenCiphertext(bytes,[&](const QString &frozen){
        BoundedStream rebased;QDataStream s(&rebased);s.setVersion(QDataStream::Qt_4_7);s<<frozen;
        const auto &original=encoded.data.bytes;s.writeRawData(original.constData()+tailAt,int(original.size()-tailAt));
        QVariant clone(type);QDataStream read(rebased.data.bytes);read.setVersion(QDataStream::Qt_4_7);
        if(!type.load(read,clone.data())||read.status()!=QDataStream::Ok||!read.atEnd()||!clone.convert(QMetaType(QMetaType::QByteArray)))fail();
        auto plain=clone.toByteArray();if(plain.isEmpty()||std::size_t(plain.size())>budget)fail();return plain;
    });
}
}
transaction::Snapshot materializeNativeModel(QAbstractListModel *model,const QString &root,transaction::Limits limits){
    packed::validateLimits(limits);if(!model||model->rowCount()<0||std::size_t(model->rowCount())>limits.items)fail();
    transaction::Snapshot result;std::size_t total=0;
    for(int row=0;row<model->rowCount();++row){
        auto value=model->data(model->index(row,0),contentType::data);if(value.metaType().id()!=QMetaType::QVariantMap)fail();
        const auto map=value.toMap();if(std::size_t(map.size())>limits.formatsPerItem)fail();transaction::Item item;
        for(auto it=map.cbegin();it!=map.cend();++it){
            const auto name=it.key();if(name.isEmpty()||std::size_t(name.size())>limits.mimeNameBytes||name.startsWith("FILE:"))fail();
            for(auto c:name)if(c.unicode()<0x21||c.unicode()>0x7e)fail();
            if(std::size_t(name.size())>limits.snapshotBytes-total)fail();total+=std::size_t(name.size());
            const auto b=materialize(it.value(),root,limits.snapshotBytes-total);total+=std::size_t(b.size());
            const auto *first=reinterpret_cast<const std::uint8_t *>(b.constData());item.emplace(name.toLatin1().toStdString(),crypto::Bytes(first,first+b.size()));
        }
        result.push_back(std::move(item));
    }
    packed::validateSnapshot(result,limits);return result;
}
}
