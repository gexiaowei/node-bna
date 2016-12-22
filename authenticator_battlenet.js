/**
 * authenticator_battlenet.js
 * @author Vivian
 * @version 1.0.0
 * copyright 2014-2016, gandxiaowei@gmail.com all rights reserved.
 */
"use strict";

const crypto = require('crypto');
const bignum = require('bignum');
const request = require('sync-request');

const server = 'http://mobile-service.blizzard.com';

const initialize_uri = "/enrollment/enroll.htm";

const synchronize_uri = "/enrollment/time.htm";

const restore_uri = "/enrollment/initiatePaperRestore.htm";

const restore_validate_uri = "/enrollment/validatePaperRestore.htm";

const accepted_region = ['EU', 'US', 'CN'];

class BattleAuthenticator {
    constructor(serial, secret) {
        if (!secret) {
            this.region = serial;
        } else {
            this.serial = serial;
            this.secret = secret;
        }
    }

    static generate(region) {
        let authenticator = new BattleAuthenticator(region);
        authenticator.initialize();
        return authenticator;
    }

    static restore(serial, restore_code) {
        let authenticator = new BattleAuthenticator(serial, 'tempsecret');
        authenticator.restore(restore_code);
        return authenticator;
    }

    static factory(serial, secret, sync) {
        let authenticator = new BattleAuthenticator(serial, secret);
        if (sync) {
            authenticator._sync = sync;
        }
        return authenticator;
    }

    initialize() {
        let enc_key = this.createKey(37);
        let data = Buffer.concat([new Buffer([1]), enc_key, Buffer.from(this.region), Buffer.from('Motorola RAZR v3')]);
        let buffer = this.send(initialize_uri, this.encrypt(data));
        let result = this.decrypt(buffer.slice(8), enc_key);
        this.sync = bignum.fromBuffer(buffer.slice(0, 8)).toNumber();
        this.serial = result.slice(20);
        this.secret = result.slice(0, 20);
    }

    restore(restore_code) {
        restore_code = BattleAuthenticatorCrypto.restore_code_from_char(restore_code);
        let serial = this.plain_serial;
        let enc_key = this.createKey(20);
        let challenge = this.send(restore_uri, serial);
        let mac = crypto.createHmac('sha1', restore_code).update(Buffer.concat([serial, challenge])).digest();
        let data = Buffer.concat([serial, this.encrypt(Buffer.concat([mac, enc_key]))]);
        let respones = this.send(restore_validate_uri, data);
        this.secret = this.decrypt(respones, enc_key);
    }

    synchronize() {
        let response = this.send(synchronize_uri);
        this.sync = bignum.fromBuffer(response).toNumber();
    }

    send(uri, data = '') {
        let method = !data ? 'GET' : 'POST';
        let response = request(method, `${server}${uri}`, {
            headers: {
                'Content-Type': 'application/octet-stream'
            },
            encoding: null,
            body: data
        });
        return response.getBody();
    }

    createKey(size) {
        return crypto.randomBytes(size);
    }

    encrypt(data) {
        return BattleAuthenticatorCrypto.encrypt(data);
    }

    decrypt(data, key) {
        return BattleAuthenticatorCrypto.decrypt(data, key);
    }

    get region() {
        return this._region.toString();
    }

    set region(region) {
        if (typeof region === 'string') region = region.toUpperCase();
        this._region = Buffer.from(region);
    }

    get serial() {
        return this._serial.toString();
    }

    set serial(serial) {
        this._serial = Buffer.from(serial);
        this._region = serial.slice(0, 2);
    }

    get secret() {
        return this._secret.toString('hex');
    }

    set secret(secret) {
        this._secret = Buffer.from(secret);
    }

    get sync() {
        return this._sync || 0;
    }

    set sync(sync) {
        this._sync = sync - Date.now();
    }

    get restore_code() {
        if (this._restore_code) {
            return this._restore_code;
        } else {
            let data = crypto.createHash('sha1').update(Buffer.concat([this.plain_serial, this._secret])).digest().slice(-10);
            return BattleAuthenticatorCrypto.restore_code_to_char(data);
        }
    }

    set restore_code(restore_code) {
        this._restore_code = restore_code;
    }

    get plain_serial() {
        return Buffer.from(this._serial.toString().replace(/-/g, '').toUpperCase());
    }

    get waiting_time() {
        return 30000;
    }

    get server_time() {
        if (this.sync) this.synchronize();
        return Date.now() + this.sync;
    }

    get code() {
        let secret = this.secret;
        let time = this.server_time / this.waiting_time;
        //TODO convert the cycle to a 8 bytes unsigned long big endian order
        let cycle = time;
        let mac = crypto.createHmac('sha1', secret).update(cycle).digest();
        let start = parseInt(mac[39], 16) * 2;
        let mac_part = mac.slice(start, 8);
        let code = parseInt(mac_part) & 0x7fffffff;
        return code;
    }
}



const RSA_MOD = bignum("104890018807986556874007710914205443157030159668034197186125678960287470894290830530618284943118405110896322835449099433232093151168250152146023319326491587651685252774820340995950744075665455681760652136576493028733914892166700899109836291180881063097461175643998356321993663868233366705340758102567742483097");
const RSA_KEY = bignum(257);
const keysize = 1024;

class BattleAuthenticatorCrypto {

    static encrypt(buffer) {
        let data = bignum(buffer.toString('hex'), 16);
        let n = data.pow(RSA_KEY).mod(RSA_MOD);
        let ret = [];
        while (n > 0) {
            let m = n.mod(256);
            ret.unshift(m.toNumber());
            n = n.div(256);
        }
        return Buffer.from(ret);
    }

    static decrypt(buffer, key) {
        let ret = [];
        return Buffer.from(buffer.map((item, index) => item ^ key[index]));
    }

    static restore_code_from_char(restore) {
        return Buffer.from(restore.split('').map(item => {
            let temp = item.charCodeAt(0);
            if (temp > 47 && temp < 58)
                temp -= 48;
            else {
                if (temp > 82) temp--; // S
                if (temp > 78) temp--; // O
                if (temp > 75) temp--; // L
                if (temp > 72) temp--; // I
                temp -= 55;
            }
            return temp;
        }));
    }

    static restore_code_to_char(data) {
        return Array.from(data).map(item => {
            let temp = item & 0x1f;
            if (temp < 10)
                temp += 48;
            else {
                temp += 55;
                if (temp > 72) temp++; // I
                if (temp > 75) temp++; // L
                if (temp > 78) temp++; // O
                if (temp > 82) temp++; // S
            }
            return String.fromCharCode(temp);
        }).join('');
    }

    static bchexdec(hex) {

    }

    static safe_dump(data) {

    }
}

module.exports = BattleAuthenticator;