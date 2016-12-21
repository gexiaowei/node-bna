/**
 * test1.js
 * @author Vivian
 * @version 1.0.0
 * copyright 2014-2016, gandxiaowei@gmail.com all rights reserved.
 */
"use strict";

const ursa = require('ursa');
const crypto = require('crypto');
const randomatic = require('randomatic');
const BN = require('bn.js');
const Promise = require('bluebird');
const request = Promise.promisify(require('request'), {multiArgs: true});
request.debug = true;

const MODEL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890";

const ENROLL_MODULUS =
    "955e4bd989f3917d2f15544a7e0504eb9d7bb66b6f8a2fe470e453c779200e5e" +
    "3ad2e43a02d06c4adbd8d328f1a426b83658e88bfd949b2af4eaf30054673a14" +
    "19a250fa4cc1278d12855b5b25818d162c6e6ee2ab4a350d401d78f6ddb99711" +
    "e72626b48bd8b5b0b7f3acf9ea3c9e0005fee59e19136cdb7c83f2ab8b0a2a99";

const ENROLL_EXPONENT = "0101";

console.log((new BN(ENROLL_EXPONENT, 16)).toBuffer());
console.log(new Buffer(ENROLL_EXPONENT, "hex"));

let pad = crypto.randomBytes(20);
let country = Buffer.from('US');
let random_model = Buffer.from(randomatic('*', '16'));
console.log(Buffer.concat([pad, country, random_model]));
let data = Buffer.from([246, 138, 160, 71, 0, 137, 171, 120, 255, 198, 206, 210, 59, 193, 190, 30, 44, 167, 82, 63, 85, 83, 76, 88, 84, 105, 115, 98, 73, 101, 84, 65, 56, 76, 56, 57, 84, 97]);
console.log(data);
// console.log(data.length);
// let data = Buffer.concat([pad, country, random_model]);

let crt = ursa.createPublicKeyFromComponents(new Buffer(ENROLL_MODULUS, "hex"), new Buffer(ENROLL_EXPONENT, "hex"));
let msg = crt.encrypt(data);
// console.log(`type: ${typeof msg}`);
// console.log(`length: ${msg.length}`);
console.log(1);
console.log(msg.length);
let correct = Buffer.from([143, 80, 192, 110, 203, 19, 102, 86, 197, 118, 69, 136, 178, 21, 243, 220, 91, 195, 13, 15, 95, 73, 52, 155, 132, 61, 201, 174, 78, 129, 2, 135, 228, 113, 183, 111, 146, 155, 40, 137, 218, 159, 116, 5, 84, 46, 238, 165, 208, 148, 161, 237, 191, 111, 213, 0, 48, 47, 144, 104, 17, 55, 124, 157, 246, 82, 61, 54, 182, 202, 57, 171, 23, 207, 97, 250, 222, 213, 88, 198, 12, 236, 177, 143, 147, 66, 249, 205, 58, 170, 194, 42, 138, 252, 72, 94, 138, 48, 168, 106, 9, 177, 229, 37, 25, 66, 208, 87, 229, 76, 85, 42, 136, 46, 246, 211, 48, 206, 149, 72, 63, 189, 198, 172, 69, 251, 45, 1]);
console.log(2);
console.log(correct);

request({
    url: 'http://mobile-service.blizzard.com/enrollment/enroll2.htm',

    method: 'POST',
    headers: {
        'Content-Type': 'application/octet-stream'
    },
    encoding: null,
    body: msg
}).then(data => {
    let buf = data[1];
    console.log(buf.length);
    console.log(buf.slice(8, 24).toString());
});
