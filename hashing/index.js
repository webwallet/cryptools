'use strict'

const crypto = require('crypto')
const ripemd160 = require('ripemd160')
const stringify = require('json-stable-stringify')

const STRINGS = {hex: 'hex', colon: ':', sha256: 'sha256'} // todo: import
const { hex, colon, sha256 } = STRINGS

const hashFunctions = {
  sha256(data, encoding = hex) {
    return crypto.createHash(sha256)
      .update(Buffer.from(data, encoding)).digest(hex)
  },
  ripemd160(data, encoding = hex) {
    return new ripemd160().update(Buffer.from(data, encoding)).digest(hex)
  }
}

function createHash(data, algorithms = [], encodings = []) {
  if (!algorithms.length) return data

  let encoding = encodings.pop()
  let algorithm = algorithms.pop()
  let hashFunction = hashFunctions[algorithm]
  let hash = hashFunction(data, encoding)

  return createHash(hash, algorithms, encodings)
}

function create({ data, algorithms = [], encodings = [],
  stringifier = stringify, delimiter = colon } = {}) {
  let params = {data, algorithms, encodings}

  if (typeof algorithms === 'string') {
    params.algorithms = algorithms.split(delimiter)
  }
  if (typeof encodings === 'string') {
    params.encodings = encodings.split(delimiter)
  }
  if (typeof data === 'object') {
    params.data = stringifier(data)
    encodings.unshift('utf8')
  }

  return createHash(
    params.data,
    params.algorithms.reverse(),
    params.encodings.reverse()
  )
}

module.exports = {
  create
}
