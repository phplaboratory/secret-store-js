'use strict';
const ecies = require('./ecies_taras.js');
const secp256k1 = require('secp256k1');

var request =require('request');

/*
request key generation
* var privateKey : string
* var docid : string
* var replicas : int
* var callback(err, encryptedDocumentKey : string)
*
* */

// test
function generateKeyRequest(privateKey,docid,replicas,secretStoreUrl) {
    return new Promise( function (resolve, reject) {
    var privateKeyBuffer = new Buffer.from(privateKey, 'hex');
    var docidBuf = new Buffer(docid,'hex');
    var signedStorageId = secp256k1.sign(docidBuf, privateKeyBuffer);
    var url = secretStoreUrl+ '/'
        + docid + '/'
        + signedStorageId.signature.toString('hex') + '0' + signedStorageId.recovery.toString(16) + '/' +
        replicas;
     request.post(url, function (error, response, body) {
        if (error) { return cb(error,null); };
        if (!response) { return cb(new Error('No response'),null); }
        if (response.statusCode != 200) { return cb(new Error( "HTTP: "+response.statusCode + " - " +response.statusMessage )); }
        return cb(null,JSON.parse(body).replace('0x', ''))
    });

    })
}

generateKeyRequest(
    'd2949e0ad0c1a76d20cdb7d9df77de43a2143035851f04661ce4c2254a074d07',
    'f5c0260c9a5ed7e007819737e7788d8db33b595374df4caf411e9d457d9c8cd3',
    0,
    "http://94.130.94.162:8083",
    function(err,done) {
        if (err) {
            console.error(err);
        } else {

            console.log("done:",done);
        }
    }
);


exports.decrypt_SecretStore= function(privateKey,data) {
    let encrypted_document_key_buffer = new Buffer(data, 'hex');
    let clen = encrypted_document_key_buffer.length - 32;
    return exports.decrypt(privateKey, {
        ephemPublicKey: encrypted_document_key_buffer.slice(0, 65),
        iv: encrypted_document_key_buffer.slice(65, 81),
        ciphertext: encrypted_document_key_buffer.slice(81, clen),
        mac: encrypted_document_key_buffer.slice(clen)
    })
}

/*
privateKey: string (hex)
encryptedKey: string (hex)

cb : function(error,done)
 */

function decryptDocumentKey(privateKey,encrytedKey, cb) {
    // exports.decrypt_SecretStore= function(privateKey,data) {
        //     let encrypted_document_key_buffer = new Buffer(encrytedKey, 'hex');
        //     let clen = encrypted_document_key_buffer.length - 32;
        //     return exports.decrypt(privateKey, {
        //         ephemPublicKey: encrypted_document_key_buffer.slice(0, 65),
        //         iv: encrypted_document_key_buffer.slice(65, 81),
        //         ciphertext: encrypted_document_key_buffer.slice(81, clen),
        //         mac: encrypted_document_key_buffer.slice(clen)
        //     })
    // }



    // return documentKey;
}

function decryptDocument(documentKey,document) {

    return decryptedDocument;
}

function encryptDocument(documentKey,document) {


    return encryptedDocument;
}
