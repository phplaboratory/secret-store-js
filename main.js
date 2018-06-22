var bitcore = require('bitcore-lib');
// var web3 = require('web3');
// var Accounts = require('web3-eth-accounts');
const EthereumTx = require('ethereumjs-tx');
const utils = require('ethereumjs-util');
const request = require('sync-request');
const secp256k1 = require('secp256k1');


//const ss_url="http://94.130.94.162:8082";
const ss_url="http://localhost:8082";




/* Step 1 */

var HDPrivateKey = bitcore.HDPrivateKey;
var hdPrivateKey = new HDPrivateKey('xprv9s21ZrQH143K2QnrsXxnSgWEn8VnQRtyGPGq825BbkuRNCJVYRobFPXGsLnMRmTphziBpyB2synPsWMCTpunVTDjjAtMuXvx2uUbFmhnxgs');
console.log('Private key:',hdPrivateKey.toString());


/* Step 2 */
var derivedByArgument = hdPrivateKey.derive("m/44'/60'/0'/0");
console.log("Private key:",derivedByArgument.privateKey.toString('hex'));
const privateKey = Buffer.from(derivedByArgument.privateKey.toString('hex'), 'hex');

/* Step 3 */
console.log('Address','0x'+utils.privateToAddress(privateKey).toString('hex'));

/* Step 4 */
//var hdPrivateKeyBoxItems = [  (new HDPrivateKey()).toBuffer(),(new HDPrivateKey()).toBuffer() ];
var hdPrivateKeyBoxItems = [  (new HDPrivateKey()).toBuffer() ];

/* Step 5 */
const storeRequester = privateKey; //private key buffer

var items = [] ;
for(var i = 0; i < hdPrivateKeyBoxItems.length;i++) {
    items.push({ 'key': utils.sha256(hdPrivateKeyBoxItems[i]), 'value': hdPrivateKeyBoxItems[i].toString('hex') })
}
console.log('Items:', items);

/* Step 6 */

for(var i = 0; i < items.length;i++) {
    var storageId = items[i]['key'];
    var signedStorageId = secp256k1.sign(storageId, privateKey);
    // var url = ss_url+ '/shadow/' + storageId.toString('hex') + '/' + signedStorageId.signature.toString('hex') + '0' + signedStorageId.recovery.toString(16) +
    var url = ss_url+ '/' + storageId.toString('hex') + '/' + signedStorageId.signature.toString('hex') + '0' + signedStorageId.recovery.toString(16) +
        '/' + '0';
    console.log("POST:",url);
    var res = request('POST', url);
    items[i]['pubKey'] = JSON.parse(res.getBody('utf8')).replace('0x', '');
}

console.log('Items:', items);

// Compose MiraBox


var boxCreatorPrivateKey = new HDPrivateKey('xprv9s21ZrQH143K2QnrsXxnSgWEn8VnQRtyGPGq825BbkuRNCJVYRobFPXGsLnMRmTphziBpyB2synPsWMCTpunVTDjjAtMuXvx2uUbFmhnxgs').derive("m/44'/0'/0'/0").privatekey;



// var BoxItem = {
//     data: encryptedWallet.encryptedWallet,
//     hash: encryptedPasswordResult.storageId,
//     key: encryptedPasswordResult.encrypted,
//     headers: {
//         type: wallet,
//         pubType: 'xpub',
//         pub: encryptedWallet.decryptedWallet.xPubKey,
//         address: address
//     },
//     meta: walletMeta
// };
//
// return new MiraBox(
//     MiraBoxType.Nominal,
//     boxCreator,
//     [boxItem],
//     boxDescription
// );



/* Step 8 decode */


for(var i = 0; i < items.length;i++) {
    var storageId = items[i]['key'];
    var signedStorageId = secp256k1.sign(storageId, privateKey);
    // var url = ss_url+ '/shadow/' + storageId.toString('hex') + '/' + signedStorageId.signature.toString('hex') + '0' + signedStorageId.recovery.toString(16) ;
    var url = ss_url+ '/' + storageId.toString('hex') + '/' + signedStorageId.signature.toString('hex') + '0' + signedStorageId.recovery.toString(16) ;
    console.log(url);
    var res = request('GET', url);
    items[i]['privKey'] = JSON.parse(res.getBody('utf8')).replace('0x', '');
}

console.log('Items:', items);


//curl http://localhost:8082/0000000000000000000000000000000000000000000000000000000000000000/de12681e0b8f7a428f12a6694a5f7e1324deef3d627744d95d51b862afc13799251831b3611ae436c452b54cdf5c4e78b361a396ae183e8b4c34519e895e623c00






