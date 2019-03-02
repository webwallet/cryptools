'use strict'

const bs58check = require('bs58check')
const createHash = require('../hashing').create

function encode(hash, { prefix = '87', encoding = 'base58check' } = {}) {
  let encoded
  let buffer

  switch (encoding) {
  case 'base58check': default:
    buffer = Buffer.from(prefix + hash, 'hex')
    encoded = bs58check.encode(buffer)
    break
  }

  return encoded
}

const generate = (({ data, hashing, format, encoder = encode, encodings = [] } = {}) => {
  let hash = createHash({data, algorithms: hashing, encodings})
  let address = encoder(hash, format)

  return address
})

function decode(address, { prefix = '87', encoding = 'base58check' } = {}) {
  let decoded

  switch (encoding) {
  case 'base58check': default:
    decoded = bs58check.decode(address).toString('hex')
    if (decoded.indexOf(prefix) === 0) {
      decoded = decoded.replace(prefix, '')
    }
    break
  }

  return decoded
}

const validate = ((decode, address, { prefix, encoding } = {}) => {
  let valid = false
  try { valid = !!decode(address, {prefix, encoding}) }
  catch(e) { /*invalid address*/ }

  return valid
}).bind(null, decode)

module.exports = {
  generate,
  validate,
  encode,
  decode
}
