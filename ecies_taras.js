'use strict';

var Promise = require('bluebird');
var secp256k1 = require('secp256k1/elliptic');
var crypto = require('crypto');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

/**
 * Compute the public key for a given private key.
 * @param {Buffer} privateKey - A 32-byte private key
 * @return {Buffer} A 65-byte public key.
 * @function
 */
function getPublic(privateKey) {
  assert(privateKey.length === 32, "Bad private key");
  // See https://github.com/wanderer/secp256k1-node/issues/46
  var compressed = secp256k1.publicKeyCreate(privateKey);
  return secp256k1.publicKeyConvert(compressed, false);
}

function sha512(msg) {
  return crypto.createHash("sha512").update(msg).digest();
}

function sha256(msg) {
  return crypto.createHash("sha256").update(msg).digest();
}


function aes256CbcEncrypt(iv, key, plaintext) {
  var cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  var firstChunk = cipher.update(plaintext);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function aes256CbcDecrypt(iv, key, ciphertext) {
  var cipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  var firstChunk = cipher.update(ciphertext);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function aes128CbcDecrypt(iv, key, ciphertext) {

  // console.log("chiper:",ciphertext);
  // console.log("iv:",iv);

  var cipher = crypto.createDecipheriv("AES-128-CTR", key, iv);

  var encoding = encoding || "binary";

  var firstChunk = cipher.update(ciphertext);
  // var firstChunk = cipher.update('','hex',encoding);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}


function hmacSha256(key, msg) {
  return crypto.createHmac("sha256", key).update(msg).digest();
}

// Compare two buffers in constant time to prevent timing attacks.
function equalConstTime(b1, b2) {
  if (b1.length !== b2.length) {
    return false;
  }
  var res = 0;
  for (var i = 0; i < b1.length; i++) {
    res |= b1[i] ^ b2[i];  // jshint ignore:line
  }
  return res === 0;
}

/**
 * Derive shared secret for given private and public keys.
 * @param {Buffer} privateKeyA - Sender's private key (32 bytes)
 * @param {Buffer} publicKeyB - Recipient's public key (65 bytes)
 * @return {Promise.<Buffer>} A promise that resolves with the derived
 * shared secret (Px, 32 bytes) and rejects on bad key.
 */
function derive(privateKeyA, publicKeyB) {
  return new Promise(function(resolve) {



    var sjcl = require('sjcl-all');
    var mykey = privateKeyA.toString('hex');
    var pubkey = publicKeyB.toString('hex');
    var secret_key_bn = new sjcl.bn(mykey);

    var secret_key = new sjcl.ecc.elGamal.secretKey(sjcl.ecc.curves.k256, secret_key_bn);

    var pub = new sjcl.ecc.elGamal.publicKey(
        sjcl.ecc.curves.k256,
        sjcl.codec.hex.toBits(pubkey.slice(2))
    );

    resolve(new Buffer(sjcl.codec.hex.fromBits( secret_key.dhJavaEc(pub)),'hex' ));

      // console.log("DH Pub: ",publicKeyB.toString('hex'));
     // console.log("DH Priv:",privateKeyA.toString('hex'));
    // resolve(secp256k1.ecdh(publicKeyB, privateKeyA));






  });
}

/**
 * Input/output structure for ECIES operations.
 * @typedef {Object} Ecies
 * @property {Buffer} iv - Initialization vector (16 bytes)
 * @property {Buffer} ephemPublicKey - Ephemeral public key (65 bytes)
 * @property {Buffer} ciphertext - The result of encryption (variable size)
 * @property {Buffer} mac - Message authentication code (32 bytes)
 */

/**
 * Encrypt message for given recepient's public key.
 * @param {Buffer} publicKeyTo - Recipient's public key (65 bytes)
 * @param {Buffer} msg - The message being encrypted
 * @param {?{?iv: Buffer, ?ephemPrivateKey: Buffer}} opts - You may also
 * specify initialization vector (16 bytes) and ephemeral private key
 * (32 bytes) to get deterministic results.
 * @return {Promise.<Ecies>} - A promise that resolves with the ECIES
 * structure on successful encryption and rejects on failure.
 */
exports.encrypt = function(publicKeyTo, msg, opts) {
  opts = opts || {};
  // Tmp variable to save context from flat promises;
  var ephemPublicKey;
  return new Promise(function(resolve) {
    var ephemPrivateKey = opts.ephemPrivateKey || crypto.randomBytes(32);
    ephemPublicKey = getPublic(ephemPrivateKey);
    resolve(derive(ephemPrivateKey, publicKeyTo));
  }).then(function(Px) {
    var hash = sha512(Px);
    var iv = opts.iv || crypto.randomBytes(16);
    var encryptionKey = hash.slice(0, 32);
    var macKey = hash.slice(32);
    var ciphertext = aes256CbcEncrypt(iv, encryptionKey, msg);
    var dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
    var mac = hmacSha256(macKey, dataToMac);
    return {
      iv: iv,
      ephemPublicKey: ephemPublicKey,
      ciphertext: ciphertext,
      mac: mac
    };
  });
};

/**
 * Decrypt message using given private key.
 * @param {Buffer} privateKey - A 32-byte private key of recepient of
 * the mesage
 * @param {Ecies} opts - ECIES structure (result of ECIES encryption)
 * @return {Promise.<Buffer>} - A promise that resolves with the
 * plaintext on successful decryption and rejects on failure.
 */
exports.decrypt = function(privateKey, opts) {
  return derive(privateKey, opts.ephemPublicKey).then(function(Px) {
    // console.log("px:",Px.toString('hex'));
    var kdfHash = crypto.createHash("sha256");
    // let ctrs = [(ctr >> 24) as u8, (ctr >> 16) as u8, (ctr >> 8) as u8, ctr as u8];
    // hasher.input(&ctrs);
    kdfHash.update(new Buffer('00000001','hex'));
    // hasher.input(secret);
    kdfHash.update(Px);
    // hasher.input(s1);
    kdfHash.update(new Buffer([]));
    // hasher.result(&mut dest[written..(written + 32)]);
    var key = kdfHash.digest();


    var ekey = key.slice(0,16);
    var mkey_material = key.slice(16,32);
    var mkey = sha256(mkey_material);



    // var hash = sha512(Px);
    // var encryptionKey = hash.slice(0, 32);
    var encryptionKey = ekey;
    // var macKey = hash.slice(32);
    // var macKey = sha256(Px.slice(16));
    var macKey = mkey;
    var dataToMac = Buffer.concat([
      opts.iv,
      // opts.ephemPublicKey,
      opts.ciphertext, new Buffer('0000','hex')
    ]);
    var realMac = hmacSha256(macKey, dataToMac);
    // console.log(realMac,opts.mac);
    assert(equalConstTime(opts.mac, realMac), "Bad MAC");
    return aes128CbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
    // return true;
  });
};

exports.publicKeyConvert = secp256k1.publicKeyConvert;
