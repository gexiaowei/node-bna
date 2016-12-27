Implementation of the Battle.net Mobile Authenticator in Node.


# Usage

``
npm install node-bna --save
``

# Method

### generate()

**generate(region)**


request new serial. valid region are EU or US or CN


### restore()
**restore(serial, restore_code)**

use serial and restore_code to restore the serial 

### factory()
**factory(serial, secret, [sync])**

to factory a battle authenticator use serial and secret
if sync is undefined, it will sync time from battlenet.

### code
**code**

the battlenet current code

### serial
**serial**

the serial code 

### secret
**secret**

the secret code 

### restore_code
**restore_code**

the restore code 

### remaining
**remaining**

the remaining time for update unit is ms
