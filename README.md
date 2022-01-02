# Mongez Encryption

A lightweight package for encrypting/decrypting and hashing data.

> Under the hood, this package is built on [crypto js](https://www.npmjs.com/package/crypto-js).

## Installation

`yarn add @mongez/encryption`

Or

`npm i @mongez/encryption`

## Usage

This package is shipped with several functions such as:

- [Mongez Encryption](#mongez-encryption)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Data Encryption](#data-encryption)
    - [Data Decryption](#data-decryption)
    - [Encryption Configurations](#encryption-configurations)
    - [md5](#md5)
    - [sha1](#sha1)
    - [sha256](#sha256)
    - [sha512](#sha512)
  - [TODO](#todo)

### Data Encryption

Before we go with data encryption or decryption, we need to define the encryption key and the algorithm used, let's see an example first then let's understand what does that mean.

```js
import AES from "crypto-js/aes";
import { encrypt } from '@mongez/encryption';

console.log(encrypt('Hello World', 'my-key', AES)); // something like SAGFHYR4TERWE3QSADFGTREW
```

In the previous example, we defined our data which is a string `Hello World` along with the encryption algorithm, which will be `AES` used here.

We can also store any type of data such objects, arrays and so on.

```js
import AES from "crypto-js/aes";
import { encrypt } from '@mongez/encryption';

console.log(encrypt({
    name: 'Hasan',
    address: {
        city: 'Cairo',
        country: 'Egypt',
    }
}, 'my-key', AES)); // something like SAGFHYR4TERWE3QSADFGTREWsadfgrtewqsaasDFERWQa
```

### Data Decryption

Now we have encrypted our data and return the ciphered text, let's reverse it back using `decrypt` function.

```js
import AES from "crypto-js/aes";
import { encrypt, decrypt } from '@mongez/encryption';

const cipheredText = encrypt({
    name: 'Hasan',
    address: {
        city: 'Cairo',
        country: 'Egypt',
    }
}, 'my-key', AES));

const data = decrypt(cipheredText, 'my-key', AES); // output {name: 'Hasan', address: {city: 'Cairo', country: 'Egypt'}}
```

> Be aware that the encryption key used in the second argument and the algorithm used in the third argument in the `encrypt` function must be used as well in the `decrypt` function as second and third arguments.

### Encryption Configurations

Instead of passing the encryption key and algorithm in every encrypt/decrypt function, we can define it using encryption function.

```js
import AES from "crypto-js/aes";
import { encrypt, decrypt, setEncryptionConfigurations } from '@mongez/encryption';

setEncryptionConfigurations({
    key: 'my-key',
    driver: AES,
});

// now let's use our functions directly.
const cipheredText = encrypt({
    name: 'Hasan',
    address: {
        city: 'Cairo',
        country: 'Egypt',
    }
}));

const data = decrypt(cipheredText); // output {name: 'Hasan', address: {city: 'Cairo', country: 'Egypt'}}
```

### md5

To generate a md5 hash code, use `md5` function.

```js
import { md5 } from '@mongez/encryption';

console.log(md5('123456')); // e10adc3949ba59abbe56e057f20f883e
```

### sha1

To generate a sha1 hash code, use `sha1` function.

```js
import { sha1 } from '@mongez/encryption';

console.log(sha1('123456')); // 7c4a8d09ca3762af61e59520943dc26494f8941b
```

### sha256

To generate a sha256 hash code, use `sha256` function.

```js
import { sha256 } from '@mongez/encryption';

console.log(sha256('123456')); // 8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92
```

### sha512

To generate a sha512 hash code, use `sha512` function.

```js
import { sha512 } from '@mongez/encryption';

console.log(sha512('123456')); // ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413
```

## TODO

- Add Unit Tests
- Add other encryption algorithms.
