const request = require('sync-request');
const secp256k1 = require('secp256k1');
const ecies = require('./ecies_taras.js');
var crypto = require('crypto');


const ss_url="http://94.130.94.162:8083";

var src ='0x1fc297810b2d89b8ec8260b5e5e778096b5ad666032bed3b2ba09686e5';
var storageId = new Buffer('f5c0260c9a5ed7e007819737e7788d8db33b595374df4caf411e9d457d9c8cd0','hex');
var signedStorageId = secp256k1.sign(storageId, new Buffer('d2949e0ad0c1a76d20cdb7d9df77de43a2143035851f04661ce4c2254a074d07','hex'));

// Document key: 0x0457923661170886a4993fdb4c0eabd4a8fcbf63e68b9dfe677ada336935472c2ce0583efef8ab448ad360f7976b8bbd702e157f459cea333f27b6e7f720e257199781f3cfa15fb58fe6840af50885a30d17763e65204576c3fc26300f0ae5a4fb48419ca6be1f47b1f1c2c212c04aeb1c327a1d51305eca5f67553d4e580f992bc3e65e1cf83d1b1dcf83f92664a51c81f647350ec4da25f2d76911eb68672f70f2bb54df42349f705d8445273ee26881
// Encode: 0x48656c6c6f6f6f776f726c6473

// var url = ss_url+ '/shadow/' + storageId.toString('hex') + '/' + signedStorageId.signature.toString('hex') + '0' + signedStorageId.recovery.toString(16) ;
var url = ss_url+ '/' + storageId.toString('hex') + '/' + signedStorageId.signature.toString('hex') + '0' + signedStorageId.recovery.toString(16) ;
console.log(url);
var res = request('GET', url);

console.log(JSON.parse(res.getBody('utf8')).replace('0x', ''));

var keyx = JSON.parse(res.getBody('utf8'));
console.log("keyx:",keyx);

var res2 = request('POST', 'https://rpc.miralab.io', {json:{
        "jsonrpc": "2.0",
        "method": "secretstore_decrypt",
        "params": [
            "0x6f5902453971a820b122d67ec5fb77e7ae50cbd5",
            "gWOQXmbuHNCcEKbIlwVxVc4XgJXY3ElQ9iX8XDLRu6t3dDNZrQyqXZ218vwpI38t6QW7Ii130PfVkXixu57trqrStAFv0ynHHVcmv9UHYLxBPDiAim8zhbEa08nQqM57",
            keyx,
            src,
        ],
        id: 1
    }
});

var v = JSON.parse(res2.getBody('utf8'))['result'].replace('0x', '');
console.log(v);
console.log(new Buffer(JSON.parse(res2.getBody('utf8'))['result'].replace('0x', ''),'hex').toString('utf8'))


var privateKey = new Buffer('d2949e0ad0c1a76d20cdb7d9df77de43a2143035851f04661ce4c2254a074d07','hex');
var encrypted_document_key = keyx.replace('0x', '');


var source = new Buffer(src.replace('0x',''),'hex');
const ivlen = 16;
ecies.decrypt_SecretStore(privateKey, encrypted_document_key  ).then(function(k) {
    // console.log("Key: ",k.toString('hex'));
    var smallKey = k.slice(0,16);
    // console.log("Length:",s.length);
    var encrypted_document = source.slice(0,source.length-ivlen);
    var iv = source.slice(source.length-ivlen,source.length);
    // console.log("",source.length,"=",encrypted_document.length,'+',iv.length,'=',encrypted_document.length+iv.length)
    var cipher = crypto.createDecipheriv("AES-128-CTR", smallKey, iv);
    var encoding = encoding || "binary";
    var firstChunk = cipher.update(encrypted_document);
    var secondChunk = cipher.final();
    console.log( Buffer.concat([firstChunk, secondChunk]).toString());
});

