/**
 * RSA encryption module using pidCrypt
 * IG requires a specific RSA encryption format that pidCrypt provides
 */

const pidCrypt = require('pidcrypt');
require('pidcrypt/rsa');
require('pidcrypt/asn1');
const pidCryptUtil = require('pidcrypt/pidcrypt_util');

/**
 * Encrypts password using IG's required RSA format
 * @param {string} password - Plain text password
 * @param {string} encryptionKey - Base64 encoded public key from IG
 * @param {string|number} timestamp - Timestamp from IG
 * @returns {string} Base64 encoded encrypted password
 */
function encryptPassword(password, encryptionKey, timestamp) {
  const rsa = new pidCrypt.RSA();
  const decodedKey = pidCryptUtil.decodeBase64(encryptionKey);
  const asn = pidCrypt.ASN1.decode(pidCryptUtil.toByteArray(decodedKey));
  const tree = asn.toHexTree();
  rsa.setPublicKeyFromASN(tree);
  
  const result = pidCryptUtil.encodeBase64(
    pidCryptUtil.convertFromHex(rsa.encrypt(`${password}|${timestamp}`))
  );
  
  return result;
}

module.exports = { encryptPassword };