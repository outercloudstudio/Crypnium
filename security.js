const { createHash, scryptSync, randomBytes, timingSafeEqual, createCipheriv, createDecipheriv, generateKeyPairSync, publicEncrypt, privateDecrypt } = require('crypto')

module.exports = {
    hash: (data) => {
        return createHash('sha256').update(data).digest('base64')
    },

    keyPair: () => {
        const { privateKey, publicKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048, // the length of your key in bits
            publicKeyEncoding: {
              type: 'spki', // recommended to be 'spki' by the Node.js docs
              format: 'pem',
            },
            privateKeyEncoding: {
              type: 'pkcs8', // recommended to be 'pkcs8' by the Node.js docs
              format: 'pem',
              // cipher: 'aes-256-cbc',
              // passphrase: 'top secret'
            },
        })
      
        return [publicKey, privateKey]
    },

    encrypt: (data, key) => {
        return publicEncrypt(
            key,
            Buffer.from(data)
          ).toString('hex')
    },

    decrypt: (data, key) => {
        let decryption

        try{
          decryption = privateDecrypt(
            key,
            Buffer.from(data, 'hex')
          ).toString('utf-8')
        }catch (err) {
          console.log('Error Decrypting: ' + err)

          decryption = null
        }

        return decryption
    },

    randomBytes: (size) => {
        return randomBytes(size).toString('hex')
    }
}