'use strict';
const ecies = require('./ecies_taras.js');
const secp256k1 = require('secp256k1');
var rp = require('request-promise');
var crypto = require('crypto');



const ivlen = 16;


/*
privateKey: string (hex)
docid: string (hex)
secretStoreUrl: string
 */

function getKeyRequest(privateKey,docid,secretStoreUrl) {
    var privateKeyBuffer = new Buffer.from(privateKey, 'hex');
    var docidBuf = new Buffer(docid, 'hex');
    var signedStorageId = secp256k1.sign(docidBuf, privateKeyBuffer);
    var url = secretStoreUrl + '/'
        + docid + '/'
        + signedStorageId.signature.toString('hex') + '0' + signedStorageId.recovery.toString(16);

    console.log("url:",url);

    var options = {
        uri: url,
        qs: {
        },
        headers: {
            'User-Agent': 'Request-Promise'
        },
        json: true
    };
    return new Promise(function (resolve, reject) {
        rp(options)
            .then(function (parsedBody) {
                resolve(parsedBody.replace('0x', ''));
            })
            .catch(function(error) {
                console.log("error:",error);
            });
    });
}




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

return: Buffer
 */

function decryptDocument(documentBigKey,document) {

    var smallKey = documentBigKey.slice(0,16);
    var source = new Buffer(document,'hex');
    var encrypted_document = source.slice(0,source.length-ivlen);
    var iv = source.slice(source.length-ivlen,source.length);
    var cipher = crypto.createDecipheriv("AES-128-CTR", smallKey, iv);
    var firstChunk = cipher.update(encrypted_document);
    var secondChunk = cipher.final();
    return Buffer.concat([firstChunk, secondChunk]);
}

/*
low: int
high: int


 */
function randomIntInc (low, high) {
    return Math.floor(Math.random() * (high - low + 1) + low);
}




/*
documentBigKey : string (hex)
document: Buffer

return: string (hex)
 */

function encryptDocument(documentBigKey,document) {

    var smallKey = documentBigKey.slice(0,16);
    var numbers = new Array(ivlen);
    for (var i = 0; i < numbers.length; i++) {
        numbers[i] = randomIntInc(0,255);
    }
    var iv  = new Buffer(numbers);
    console.log("iv:",iv);
    var cipher = crypto.createCipheriv("AES-128-CTR", smallKey, iv);
    var firstChunk = cipher.update(new Buffer(document));
    var secondChunk = cipher.final();
    return Buffer.concat([firstChunk, secondChunk,iv]);
}


