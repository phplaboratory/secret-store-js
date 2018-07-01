const request = require('sync-request');
const ethKey = require('keythereum');
const ethUtil = require('ethereumjs-util');
const ss_url="http://94.130.94.162:8082";

var password = "gWOQXmbuHNCcEKbIlwVxVc4XgJXY3ElQ9iX8XDLRu6t3dDNZrQyqXZ218vwpI38t6QW7Ii130PfVkXixu57trqrStAFv0ynHHVcmv9UHYLxBPDiAim8zhbEa08nQqM57";

var res = request('POST', 'https://rpc.miralab.io', {json:{
        "jsonrpc": "2.0",
        "method": "parity_exportAccount",
        "params": [
            "0x6f5902453971a820b122d67ec5fb77e7ae50cbd5",
            "gWOQXmbuHNCcEKbIlwVxVc4XgJXY3ElQ9iX8XDLRu6t3dDNZrQyqXZ218vwpI38t6QW7Ii130PfVkXixu57trqrStAFv0ynHHVcmv9UHYLxBPDiAim8zhbEa08nQqM57"
      ],
        id: 1
    }
});

// console.log(JSON.parse( res.body.toString())['result']);
var account = JSON.parse( res.body.toString())['result'];
let ethPrivateKey = ethKey.recover(password, account);
console.log(ethPrivateKey.toString('hex'));

