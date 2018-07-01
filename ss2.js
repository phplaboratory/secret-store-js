'use strict';
const ecies = require('./ecies_taras.js');
const secp256k1 = require('secp256k1');
var rp = require('request-promise');

function generateKeyRequest(privateKey,docid,replicas,secretStoreUrl) {

    var privateKeyBuffer = new Buffer.from(privateKey, 'hex');
    var docidBuf = new Buffer(docid, 'hex');
    var signedStorageId = secp256k1.sign(docidBuf, privateKeyBuffer);
    var url = secretStoreUrl + '/'
        + docid + '/'
        + signedStorageId.signature.toString('hex') + '0' + signedStorageId.recovery.toString(16) + '/' +
        replicas;

    var options = {
        method: 'POST',
        uri: url,
        body: {},
        json: true
    };

    return new Promise(function (resolve, reject) {
        rp(options)
            .then(function (parsedBody) {
                resolve(parsedBody.replace('0x', ''));
            })
            .catch(reject);
    });
}

/*
privateKey: string (hex)
encryptedKey: string (hex)
 */

function decryptDocumentKey(privateKey,encrytedKey) {
    let encrypted_document_key_buffer = new Buffer(encrytedKey, 'hex');
    let clen = encrypted_document_key_buffer.length - 32;
    return ecies.decrypt(privateKey, {
        ephemPublicKey: encrypted_document_key_buffer.slice(0, 65),
        iv: encrypted_document_key_buffer.slice(65, 81),
        ciphertext: encrypted_document_key_buffer.slice(81, clen),
        mac: encrypted_document_key_buffer.slice(clen)
    })
}


/*
documentBigKey : string (hex)
document: string (hex)
 */

function decryptDocument(documentBigKey,document) {
    const ivlen = 16;
    var smallKey = documentBigKey.slice(0,16);
    var source = new Buffer(document,'hex');
    var encrypted_document = source.slice(0,source.length-ivlen);
    var iv = source.slice(source.length-ivlen,source.length);
    var cipher = crypto.createDecipheriv("AES-128-CTR", smallKey, iv);
    var firstChunk = cipher.update(encrypted_document);
    var secondChunk = cipher.final();
    return Buffer.concat([firstChunk, secondChunk]).toString();
}


generateKeyRequest(
    'd2949e0ad0c1a76d20cdb7d9df77de43a2143035851f04661ce4c2254a074d07',
    'f5c0260c9a5ed7e007819737e7788d8db33b595374df4caf411e9d457d9c4ca3',
    0,
    "http://94.130.94.162:8083",
)
    .then( function(encrytedKey) {
        // console.log(encrytedKey);
        return decryptDocumentKey('d2949e0ad0c1a76d20cdb7d9df77de43a2143035851f04661ce4c2254a074d07',encrytedKey)
    })
    .then(console.log)
    .catch(console.error);
