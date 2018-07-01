'use strict';

const ethUtil = require('ethereumjs-util');
var doc = "Helloooworlds";


const request = require('sync-request');

var bitcore = require('bitcore-lib');
const utils = require('ethereumjs-util');
const secp256k1 = require('secp256k1');

const ecies = require('./ecies_taras.js');

//const ss_url="http://94.130.94.162:8082";
const ss_url="http://94.130.94.162:8083";



/* Step 1 */
var HDPrivateKey = bitcore.HDPrivateKey;
var hdPrivateKey = new HDPrivateKey('xprv9s21ZrQH143K2QnrsXxnSgWEn8VnQRtyGPGq825BbkuRNCJVYRobFPXGsLnMRmTphziBpyB2synPsWMCTpunVTDjjAtMuXvx2uUbFmhnxgs');
console.log('Private key:',hdPrivateKey.toString());


/* Step 2 */
var derivedByArgument = hdPrivateKey.derive("m/44'/60'/0'/3");
console.log("Private key A:",derivedByArgument.privateKey.toString('hex'));
const privateKey = Buffer.from(derivedByArgument.privateKey.toString('hex'), 'hex'); // key used for request

/* Step 3 */
console.log('Address A','0x'+utils.privateToAddress(privateKey).toString('hex'));

/* Step 4 */
//var hdPrivateKeyBoxItems = [  (new HDPrivateKey()).toBuffer(),(new HDPrivateKey()).toBuffer() ];
var hdPrivateKeyBoxItem =   new Buffer(doc) ;



/* Step 6 */


var storageId = utils.sha256(hdPrivateKeyBoxItem);
console.log("Storage id:",storageId.toString('hex'));
// var signedStorageId = secp256k1.sign(storageId, privateKey);
var signedStorageId = secp256k1.sign(storageId, new Buffer('d2949e0ad0c1a76d20cdb7d9df77de43a2143035851f04661ce4c2254a074d07','hex'));
var url = ss_url+ '/'
    + storageId.toString('hex') + '/'
    + signedStorageId.signature.toString('hex') + '0' + signedStorageId.recovery.toString(16) + '/' +
    '0';
console.log("POST:",url);
var res = request('POST', url);
var encrypted_document_key  = JSON.parse(res.getBody('utf8')).replace('0x', '');

// const request = require('request');
// var r = request('https://api.nasa.gov/planetary/apod?api_key=DEMO_KEY', { json: true });
// console.log(r);



var encodeHexData = '0x'+(new Buffer(doc)).toString('hex');
console.log(encodeHexData);
var documentKey = '0x'+encrypted_document_key.toString('hex');
console.log("Document key:",documentKey);

console.log("Encode:",encodeHexData);

// var request = require('sync-request');
var res = request('POST', 'https://rpc.miralab.io', {json:{
    "jsonrpc": "2.0",
    "method": "secretstore_encrypt",
    "params": [
        "0x6f5902453971a820b122d67ec5fb77e7ae50cbd5",
        "gWOQXmbuHNCcEKbIlwVxVc4XgJXY3ElQ9iX8XDLRu6t3dDNZrQyqXZ218vwpI38t6QW7Ii130PfVkXixu57trqrStAFv0ynHHVcmv9UHYLxBPDiAim8zhbEa08nQqM57",
        documentKey,
        encodeHexData
    ],
    id: 1
}
});

console.log(res.getBody().toString());
