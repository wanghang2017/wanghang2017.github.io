
'use strict'

if (process.env.NODE_ENV === 'production') {
  module.exports = require('./btcsnap.cjs.production.min.js')
} else {
  module.exports = require('./btcsnap.cjs.development.js')
}
