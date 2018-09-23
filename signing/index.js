'use strict'

const elliptic = require('elliptic')
const ecdsaEd25519 = new elliptic.ec('ed25519')
const eddsaEd25519 = new elliptic.eddsa('ed25519')

const schemes = {
  'ecdsa-ed25519': {
    verify: (message, signature, publicKey, encoding = 'hex') => {
      return ecdsaEd25519.verify(message, signature, publicKey, encoding)
    }
  },
  'eddsa-ed25519': {
    verify: (message, signature, publicKey) => {
      return eddsaEd25519.verify(message, signature, publicKey)
    }
  }
}

function verify({scheme, message, signature, publicKey, encoding}) {
  let someScheme = schemes[scheme]
  if (!someScheme) return false

  return someScheme.verify(message, signature, publicKey, encoding)
}

module.exports = {
  verify
}
