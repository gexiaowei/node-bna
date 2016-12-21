/**
 * authenticator.js
 * @author Vivian
 * @version 1.0.0
 * copyright 2014-2016, gandxiaowei@gmail.com all rights reserved.
 */
"use strict";

const crypto = require('crypto');
const b32 = require('thirty-two');
const {totp} = require('notp');

class Authenticator {
    constructor() {

    }

    generateOtpKey() {
        return crypto.randomBytes(20);
    }

    decodeAuthKey(key) {
        let unformatted = key.replace(/\W+/g, '').toUpperCase();
        return b32.decode(unformatted);
    }

    encodeAuthKey(key) {
        let base32 = b32.encode(key).toString('utf8').replace(/=/g, '');
        return base32.toLowerCase().replace(/(\w{4})/g, "$1 ").trim();
    }

    generateAuthToken(key) {
        return totp.gen(this.decodeAuthKey(key))
    }
}

let auth = new Authenticator();

console.log(auth.generateAuthToken('DPI45HCEBCJK6HG7'));
