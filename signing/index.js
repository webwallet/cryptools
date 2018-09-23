'use strict'

const elliptic = require('elliptic')
const ecdsaEd25519 = new elliptic.ec('ed25519')
const eddsaEd25519 = new elliptic.eddsa('ed25519')

const schemes = {
  'ecdsa-ed25519': {
    create: (message, secret) => {
      return ecdsaEd25519.sign(message, secret).toDER('hex')
    },
    verify: (message, signature, publicKey, encoding = 'hex') => {
      return ecdsaEd25519.verify(message, signature, publicKey, encoding)
    }
  },
  'eddsa-ed25519': {
    create: (message, secret) => {
      return eddsaEd25519.sign(message, secret).toHex()
    },
    verify: (message, signature, publicKey) => {
      return eddsaEd25519.verify(message, signature, publicKey)
    }
  }
}

function create({ scheme, message, secret } = {}) {
  let someScheme = schemes[scheme]
  if (!someScheme) return {error: 'invalid-signature-scheme'}

  return someScheme.create(message, secret)
}

function verify({ scheme, message, signature, publicKey, encoding } = {}) {
  let someScheme = schemes[scheme]
  if (!someScheme) return {error: 'invalid-signature-scheme'}

  return someScheme.verify(message, signature, publicKey, encoding)
}

module.exports = {
  create,
  verify
}
