/**
 * authenticator_battlenet.js
 * @author Vivian
 * @version 1.0.0
 * copyright 2014-2016, gandxiaowei@gmail.com all rights reserved.
 */
"use strict";
"use strict";

const crypto = require('crypto');
const Promise = require('bluebird');
const bignum = require('bignum');
const request = Promise.promisify(require('request'), { multiArgs: true });
request.debug = true;

const server = 'http://mobile-service.blizzard.com';

const initialize_uri = "/enrollment/enroll.htm";

const synchronize_uri = "/enrollment/time.htm";

const restore_uri = "/enrollment/initiatePaperRestore.htm";

const restore_validate_uri = "/enrollment/validatePaperRestore.htm";

const accepted_region = ['EU', 'US', 'CN'];


const GENERATE_SIZE = 45;
const SYNC_SIZE = 8;
const RESTORE_CHALLENGE_SIZE = 32;
const RESTORE_VALIDATE_SIZE = 20;

class BattleAuthenticator {
    constructor(serial, secret = null) {
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

    static factory(serial, secret, sync = null) {
        let authenticator = new BattleAuthenticator(serial, secret);
        if (sync) {
            authenticator.sync = sync;
        }
        return authenticator;
    }

    initialize() {
        let enc_key = this.createKey(37);
        let data = Buffer.concat([new Buffer([1]), enc_key, Buffer.from(this.region), Buffer.from('Motorola RAZR v3')]);
        return this.send(initialize_uri, GENERATE_SIZE, this.encrypt(data))
            .then(buf => {
                let result = this.decrypt(buf.slice(8), enc_key);
                this.sync = bignum.fromBuffer(buf.slice(0, 8)).toNumber();
                this.serial = Buffer.from(result.slice(0, 20)).toString('hex');
                this.secret = Buffer.from(result.slice(20)).toString();
            })
            .catch(error => {
                console.error(error);
            });
    }

    restore() {
        let serial = this.plain_serial;
        let restore_code = BattleAuthenticatorCrypto.restore_code_from_char(this.restore_code);
        let enc_key = this.createKey(20);
        return this.send(restore_uri, RESTORE_CHALLENGE_SIZE, serial)
            .then(challenge => crypto.createHmac('sha1', restore_code).update(challenge).digest('hex'))
            .then(mac => Buffer.concat([Buffer.from(serial), this.encrypt(Buffer.concat([mac, enc_key]))]))
            .then(data => this.send(restore_validate_uri, RESTORE_VALIDATE_SIZE, data))
            .then(data => this.decrypt(data, enc_key))
            .then(data => {
                this.secret = data;
                return data;
            })
            .then(this.synchronize)
    }

    synchronize() {
        return this.send(synchronize_uri, SYNC_SIZE)
            .then(data => {
                this.sync = data;
                return sync;
            });
    }


    send(uri, response_size, data = '') {
        let host = this.server;
        let method = !data ? 'GET' : 'POST';
        console.log(data);
        return request({
            url: `${host}${uri}`,
            method,
            headers: {
                'Content-Type': 'application/octet-stream',
                'Content-length': data.length
            },
            encoding: null,
            body: data
        }).then(data => data[1]);
    }

    servertime() {
        if (!this.sync) {
            this.synchronize();
        }
        return Date.now() + this.sync;
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
        if (!this._region) {
            throw new Error('Region must be set.')
        }
        return this._region;
    }

    set region(region) {
        region = !!region ? region.toUpperCase() : '';
        if (accepted_region.indexOf(region) == -1) {
            throw new Error(`Invalid region provided : ${region}`);
        }
        this._region = region;
    }

    get serial() {
        return this._serial;
    }

    set serial(serial) {
        console.log(`serial:${serial}`);
        this._region = serial.substr(0, 2).toUpperCase();
        this._serial = serial;
    }

    get secret() {
        return this._secret;
    }

    set secret(secret) {
        console.log(`secret:${secret}`);
        this._secret = typeof secret === 'string' ? Buffer.from(secret) : secret;
    }

    get sync() {
        return this._sync || 0;
    }

    set sync(sync) {
        console.log(`sync:${sync}`);
        this._sync = sync;
    }

    get plain_serial() {
        return this._serial.replace('-', '').toUpperCase();
    }

    get restore_code() {
        let serial = this.plain_serial;
        let secret = Buffer.from(this.secret);
        //TODO add data calculate
        let data = '';
        return BattleAuthenticatorCrypto.restore_code_to_char(data);
    }

    get server() {
        return `${server}`
    }

    set restore_code(restore_code) {
        this._restore_code = restore_code;
    }

    get restore_code() {
        return this._restore_code.toUpperCase();
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

    }

    static restore_code_to_char(data) {

    }

    static bchexdec(hex) {

    }

    static safe_dump(data) {

    }
}

BattleAuthenticator.generate('EU');