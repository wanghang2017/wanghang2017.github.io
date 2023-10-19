'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var bitcoinjsLib = require('bitcoinjs-lib');
var bs58check = require('bs58check');
var bs58check__default = _interopDefault(bs58check);
var snapsUi = require('@metamask/snaps-ui');
var bip32$1 = require('bip32');
var ecc = _interopDefault(require('@bitcoinerlab/secp256k1'));
var BN = _interopDefault(require('bn.js'));
var ECPairFactory = _interopDefault(require('ecpair'));
var CryptoJs = _interopDefault(require('crypto-js'));
var bitcoinMessage = _interopDefault(require('bitcoinjs-message'));

var ScriptType;
(function (ScriptType) {
  ScriptType["P2PKH"] = "P2PKH";
  ScriptType["P2SH_P2WPKH"] = "P2SH-P2WPKH";
  ScriptType["P2WPKH"] = "P2WPKH";
  ScriptType["P2TR"] = "P2TR";
})(ScriptType || (ScriptType = {}));
var BitcoinNetwork;
(function (BitcoinNetwork) {
  BitcoinNetwork["Main"] = "main";
  BitcoinNetwork["Test"] = "test";
})(BitcoinNetwork || (BitcoinNetwork = {}));
var KeyOptions;
(function (KeyOptions) {
  KeyOptions["Password"] = "password";
  KeyOptions["Credential"] = "credential";
  KeyOptions["PubKey"] = "pubkey";
})(KeyOptions || (KeyOptions = {}));
const LightningAccount = /*#__PURE__*/Buffer.from('Lightning').readInt32BE();
const LNHdPath = `m/84'/0'/${LightningAccount}'/0/0`;

function getNetwork(network) {
  switch (network) {
    case BitcoinNetwork.Main:
      return bitcoinjsLib.networks.bitcoin;
    case BitcoinNetwork.Test:
      return bitcoinjsLib.networks.testnet;
    default:
      throw Error('Network net exist');
  }
}

class SnapError extends Error {
  constructor(code) {
    super();
    this.code = code;
  }
  static of({
    code,
    message
  }) {
    const snapError = new SnapError(code);
    snapError.message = message;
    return snapError;
  }
}

const PsbtValidateErrors = {
  InputsDataInsufficient: {
    code: 10001,
    message: 'Not all inputs have prev Tx raw hex'
  },
  InputsNetworkNotMatch: {
    code: 10002,
    message: 'Not every input matches network'
  },
  OutputsNetworkNotMatch: {
    code: 10003,
    message: 'Not every output matches network'
  },
  InputNotSpendable: {
    code: 10004,
    message: 'Not all inputs belongs to current account'
  },
  ChangeAddressInvalid: {
    code: 10005,
    message: `Change address doesn't belongs to current account`
  },
  FeeTooHigh: {
    code: 10006,
    message: 'Too much fee'
  },
  AmountNotMatch: {
    code: 10007,
    message: 'Transaction input amount not match'
  }
};

const RequestErrors = {
  NoPermission: {
    code: 20000,
    message: 'Unauthorized to perform action.'
  },
  RejectKey: {
    code: 20001,
    message: 'User reject to access the key'
  },
  RejectSign: {
    code: 20002,
    message: 'User reject the sign request'
  },
  SignInvalidPath: {
    code: 20003,
    message: 'invalid path'
  },
  SignFailed: {
    code: 20004,
    message: 'Sign transaction failed'
  },
  NetworkNotMatch: {
    code: 20005,
    message: 'Network not match'
  },
  ScriptTypeNotSupport: {
    code: 20006,
    message: 'ScriptType is not supported.'
  },
  MethodNotSupport: {
    code: 20007,
    message: 'Method not found.'
  },
  ActionNotSupport: {
    code: 20008,
    message: 'Action not supported'
  },
  UserReject: {
    code: 20009,
    message: 'User rejected the request.'
  },
  KeyNotSupported: {
    code: 20010,
    message: 'Key cannot be recognized'
  },
  DomainNotAllowed: {
    code: 20011,
    message: 'Domain not allowed'
  }
};

const InvoiceErrors = {
  AmountNotValid: {
    code: 30001,
    message: 'Amount is not valid'
  }
};

const DOMAIN_WHITELIST = [/\.justsnap\.io$/];
const validateNetwork = async (snap, network) => {
  // const snapNetwork = await getPersistedData(snap, 'network', '');
  // if (snapNetwork && network !== snapNetwork) {
  //   throw SnapError.of(RequestErrors.NetworkNotMatch);
  // }
};
const validateDomain = async domain => {
  const isDomainValid = DOMAIN_WHITELIST.some(pattern => pattern.test(domain));
  if (!isDomainValid) {
    throw SnapError.of(RequestErrors.DomainNotAllowed);
  }
};
const validateRequest = async (snap, origin, request) => {
  switch (request.method) {
    case 'btc_getPublicExtendedKey':
    case 'btc_signPsbt':
      await validateNetwork();
      break;
    case 'btc_getLNDataFromSnap':
    case 'btc_saveLNDataToSnap':
    case 'btc_signLNInvoice':
      await validateDomain(origin);
  }
};

// https://github.com/satoshilabs/slips/blob/master/slip-0132.md#registered-hd-version-bytes
const xpubPrefixes = {
  'xpub': '0488b21e',
  'tpub': '043587cf',
  'ypub': '049d7cb2',
  'upub': '044a5262',
  'zpub': '04b24746',
  'vpub': '045f1cf6'
};
const scriptTypeToXpubPrefix = {
  [ScriptType.P2PKH]: {
    main: 'xpub',
    test: 'tpub'
  },
  [ScriptType.P2SH_P2WPKH]: {
    main: 'ypub',
    test: 'upub'
  },
  [ScriptType.P2WPKH]: {
    main: 'zpub',
    test: 'vpub'
  },
  [ScriptType.P2TR]: {
    main: 'xpub',
    test: 'tpub'
  }
};
const convertXpub = (xpub, to, network) => {
  const net = network === bitcoinjsLib.networks.bitcoin ? BitcoinNetwork.Main : BitcoinNetwork.Test;
  const xpubPrefix = scriptTypeToXpubPrefix[to][net];
  let data = bs58check.decode(xpub);
  data = data.slice(4);
  data = Buffer.concat([Buffer.from(xpubPrefixes[xpubPrefix], "hex"), data]);
  return bs58check.encode(data);
};

const SATS_PER_BTC = /*#__PURE__*/new BN(1e8, 10);
const DIVISORS = {
  m: /*#__PURE__*/new BN(1e3, 10),
  u: /*#__PURE__*/new BN(1e6, 10),
  n: /*#__PURE__*/new BN(1e9, 10),
  p: /*#__PURE__*/new BN(1e12, 10)
};
const hrpToSatoshi = hrp => {
  let divisor, value;
  if (hrp.slice(-1).match(/^[munp]$/)) {
    divisor = hrp.slice(-1);
    value = hrp.slice(0, -1);
  } else if (hrp.slice(-1).match(/^[^munp0-9]$/)) {
    throw SnapError.of(InvoiceErrors.AmountNotValid);
  } else {
    value = hrp;
  }
  if (!value.match(/^\d+$/)) {
    throw SnapError.of(InvoiceErrors.AmountNotValid);
  }
  const valueBN = new BN(value, 10);
  const satoshisBN = divisor ? valueBN.mul(SATS_PER_BTC).div(DIVISORS[divisor]) : valueBN.mul(SATS_PER_BTC);
  return satoshisBN.toString();
};

const trimHexPrefix = key => key.startsWith('0x') ? key.substring(2) : key;

const getPersistedData = async (snap, key, defaultValue) => {
  const persistedData = await snap.request({
    method: 'snap_manageState',
    params: {
      operation: 'get'
    }
  });
  if (persistedData && persistedData[key]) {
    return persistedData[key];
  }
  return defaultValue;
};
const updatePersistedData = async (snap, key, value) => {
  const persistedData = await snap.request({
    method: 'snap_manageState',
    params: {
      operation: 'get'
    }
  });
  const updatedData = {
    ...persistedData,
    [key]: value
  };
  await snap.request({
    method: 'snap_manageState',
    params: {
      operation: 'update',
      newState: updatedData
    }
  });
};

const bip32 = /*#__PURE__*/bip32$1.BIP32Factory(ecc);
const pathMap = {
  [ScriptType.P2PKH]: ['m', "44'", "0'"],
  [ScriptType.P2SH_P2WPKH]: ['m', "49'", "0'"],
  [ScriptType.P2WPKH]: ['m', "84'", "0'"],
  [ScriptType.P2TR]: ['m', "86'", "0'"]
};
const CRYPTO_CURVE = 'secp256k1';
async function getHDRootNode(snap, network, scriptType = ScriptType.P2PKH) {
  const path = [...pathMap[scriptType]];
  if (network != bitcoinjsLib.networks.bitcoin) {
    path[path.length - 1] = "1'";
  }
  const slip10Node = await snap.request({
    method: 'snap_getBip32Entropy',
    params: {
      path,
      curve: CRYPTO_CURVE
    }
  });
  const privateKeyBuffer = Buffer.from(trimHexPrefix(slip10Node.privateKey), 'hex');
  const chainCodeBuffer = Buffer.from(trimHexPrefix(slip10Node.chainCode), 'hex');
  const node = bip32.fromPrivateKey(privateKeyBuffer, chainCodeBuffer, network);
  //@ts-ignore
  // ignore checking since no function to set depth for node
  node.__DEPTH = slip10Node.depth;
  //@ts-ignore
  // ignore checking since no function to set index for node
  node.__INDEX = slip10Node.index;
  const mfp = slip10Node.masterFingerprint.toString(16).padStart(8, '0');
  return {
    node: node.deriveHardened(0),
    mfp
  };
}

function privateKeyToWIF(privateKeyHex) {
  const versionByte = Buffer.from([0x80]); // Mainnet version byte
  const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
  const extendedPrivateKey = Buffer.concat([versionByte, privateKeyBytes]);
  return bs58check__default.encode(extendedPrivateKey);
}
function getAddress(network, publicKey, scriptType) {
  const bufferPublicKey = Buffer.from(publicKey, 'hex');
  const hash = bitcoinjsLib.crypto.hash160(bufferPublicKey);
  const addresses = {};
  if (network === bitcoinjsLib.networks.bitcoin) {
    addresses['P2PKH'] = bitcoinjsLib.address.toBase58Check(hash, 0);
    const result = bitcoinjsLib.payments.p2sh({
      redeem: bitcoinjsLib.payments.p2wpkh({
        pubkey: bufferPublicKey,
        network
      })
    });
    addresses['P2SH-P2WPKH'] = result.address;
    addresses['P2WPKH'] = bitcoinjsLib.address.toBech32(hash, 0, 'bc');
    const p2trInstance = bitcoinjsLib.payments.p2tr({
      internalPubkey: bufferPublicKey.slice(1),
      network
    });
    const tapRootAddress = p2trInstance.address;
    addresses['P2TR'] = tapRootAddress;
  } else if (network === bitcoinjsLib.networks.testnet) {
    addresses['P2PKH'] = bitcoinjsLib.address.toBase58Check(hash, 111);
    const result = bitcoinjsLib.payments.p2sh({
      redeem: bitcoinjsLib.payments.p2wpkh({
        pubkey: bufferPublicKey,
        network
      })
    });
    addresses['P2SH-P2WPKH'] = result.address;
    addresses['P2WPKH'] = bitcoinjsLib.address.toBech32(hash, 0, 'tb');
    const p2trInstance = bitcoinjsLib.payments.p2tr({
      internalPubkey: bufferPublicKey.slice(1),
      network
    });
    const tapRootAddress = p2trInstance.address;
    addresses['P2TR'] = tapRootAddress;
  }
  console.log('addresses...', addresses);
  if (scriptType) {
    return addresses[scriptType];
  }
  return addresses;
}

async function getExtendedPublicKey(origin, snap, scriptType, network) {
  const networkName = network == bitcoinjsLib.networks.bitcoin ? 'mainnet' : 'testnet';
  switch (scriptType) {
    case ScriptType.P2PKH:
    case ScriptType.P2WPKH:
    case ScriptType.P2SH_P2WPKH:
    case ScriptType.P2TR:
      const result = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: snapsUi.panel([snapsUi.heading('Access your extended public key'), snapsUi.text(`Do you want to allow ${origin} to access Bitcoin ${networkName} ${scriptType} extended public key?`)])
        }
      });
      if (result) {
        const {
          node: accountNode,
          mfp
        } = await getHDRootNode(snap, network, scriptType);
        const address = getAddress(network, accountNode.publicKey.toString('hex'), scriptType);
        const extendedPublicKey = accountNode.neutered();
        let xpub = extendedPublicKey.toBase58();
        if (scriptType !== ScriptType.P2TR) {
          xpub = convertXpub(xpub, scriptType, network);
        }
        return {
          mfp,
          xpub,
          address
        };
      } else {
        throw SnapError.of(RequestErrors.RejectKey);
      }
    default:
      throw SnapError.of(RequestErrors.ScriptTypeNotSupport);
  }
}

async function getAllXpubs(origin, snap) {
  const result = await snap.request({
    method: 'snap_dialog',
    params: {
      type: 'confirmation',
      content: snapsUi.panel([snapsUi.heading('Access your extended public key'), snapsUi.text(`${origin} is trying to access your Bitcoin Legacy, SegWit, TapRoot and Native SegWit extended public keys.`)])
    }
  });
  try {
    if (result) {
      let xfp = '';
      const xpubs = [];
      const accounts = [];
      await Promise.all(Object.values(BitcoinNetwork).map(async bitcoinNetwork => {
        const network = bitcoinNetwork === BitcoinNetwork.Main ? bitcoinjsLib.networks.bitcoin : bitcoinjsLib.networks.testnet;
        await Promise.all(Object.values(ScriptType).map(async scriptType => {
          const {
            node: accountNode,
            mfp
          } = await getHDRootNode(snap, network, scriptType);
          xfp = xfp || mfp;
          const extendedPublicKey = accountNode.neutered();
          const deriveAccount = accountNode.derive(0).derive(0);
          let xpub = extendedPublicKey.toBase58();
          if (scriptType !== ScriptType.P2TR) {
            xpub = convertXpub(xpub, scriptType, network);
          }
          xpubs.push(xpub);
          accounts.push({
            xpub,
            scriptType,
            network: bitcoinNetwork,
            privateKey: deriveAccount.privateKey.toString('hex'),
            wif: deriveAccount.toWIF(),
            address: getAddress(network, deriveAccount.publicKey.toString('hex'), scriptType)
          });
        }));
      }));
      console.log('accounts', accounts);
      return {
        mfp: xfp,
        xpubs,
        accounts
      };
    }
    throw SnapError.of(RequestErrors.RejectKey);
  } catch (e) {
    console.log('error', e);
    return {
      mfp: '',
      xpubs: [],
      accounts: []
    };
  }
}

const ECPair = /*#__PURE__*/ECPairFactory(ecc);
class AccountSigner {
  constructor(accountNode, mfp) {
    this.node = accountNode;
    this.publicKey = this.node.publicKey;
    this.fingerprint = mfp || this.node.fingerprint;
    this.keyPair = ECPair.fromPrivateKey(this.node.privateKey, {
      compressed: true
    });
  }
  getTapRootSinger(path = '0/0') {
    const tapAccountSinger = this.derivePath(path);
    const tweakedSinger = tapAccountSinger.node.tweak(bitcoinjsLib.crypto.taggedHash('TapTweak', tapAccountSinger.node.publicKey.slice(1)));
    return tweakedSinger;
  }
  derivePath(path) {
    try {
      let splitPath = path.split('/');
      if (splitPath.length > 2) {
        splitPath = splitPath.slice(-2);
      }
      const childNode = splitPath.reduce((prevHd, indexStr) => {
        let index;
        if (indexStr.slice(-1) === `'`) {
          index = parseInt(indexStr.slice(0, -1), 10);
          return prevHd.deriveHardened(index);
        } else {
          index = parseInt(indexStr, 10);
          const node = prevHd.derive(index);
          return node;
        }
      }, this.node);
      return new AccountSigner(childNode, this.fingerprint);
    } catch (e) {
      throw new Error('invalid path');
    }
  }
  sign(hash) {
    return this.keyPair.sign(hash);
  }
  signSchnorr(hash) {
    return this.keyPair.signSchnorr(hash);
  }
}
const validator = (pubkey, msghash, signature) => {
  return ECPair.fromPublicKey(pubkey).verify(msghash, signature);
};
const schnorrValidator = (pubkey, msghash, signature) => ecc.verifySchnorr(msghash, pubkey, signature);

class PsbtHelper {
  constructor(psbt, network) {
    this.network = getNetwork(network);
    this.tx = psbt;
  }
  get inputAmount() {
    return this.tx.data.inputs.reduce((total, input, index) => {
      const vout = this.tx.txInputs[index].index;
      if (input.nonWitnessUtxo) {
        const prevTx = bitcoinjsLib.Transaction.fromHex(input.nonWitnessUtxo.toString('hex'));
        return total + prevTx.outs[vout].value;
      } else if (input.witnessUtxo) {
        return total + input.witnessUtxo.value;
      }
      return total;
    }, 0);
  }
  get sendAmount() {
    return this.tx.txOutputs.filter(output => !this.changeAddresses.includes(output.address)).reduce((amount, output) => amount + output.value, 0);
  }
  get fee() {
    const outputAmount = this.tx.txOutputs.reduce((amount, output) => amount + output.value, 0);
    return this.inputAmount - outputAmount;
  }
  get fromAddresses() {
    return this.tx.data.inputs.map((input, index) => {
      if (input.nonWitnessUtxo) {
        const prevOuts = bitcoinjsLib.Transaction.fromHex(input.nonWitnessUtxo.toString('hex')).outs;
        const vout = this.tx.txInputs[index].index;
        return bitcoinjsLib.address.fromOutputScript(prevOuts[vout].script, this.network);
      } else if (input.witnessUtxo) {
        return bitcoinjsLib.address.fromOutputScript(input.witnessUtxo.script, this.network);
      }
      return undefined;
    });
  }
  get toAddresses() {
    return this.tx.txOutputs.map(output => output.address).filter(address => !this.changeAddresses.includes(address));
  }
  get changeAddresses() {
    return this.tx.data.outputs.map((output, index) => output.bip32Derivation ? this.tx.txOutputs[index].address : undefined).filter(address => !!address);
  }
}

const fromHdPathToObj = hdPath => {
  const regex = /(\d)+/g;
  const numbers = hdPath.match(regex);
  return {
    purpose: numbers && numbers[0],
    coinType: numbers && numbers[1],
    account: numbers && numbers[2],
    change: numbers && numbers[3],
    index: numbers && numbers[4]
  };
};
const parseLightningPath = hdPath => {
  const regex = /(\d'?)+/g;
  const numbers = hdPath.match(regex);
  const isHardened = str => {
    return str.indexOf("'") !== -1;
  };
  return {
    purpose: {
      value: numbers && numbers[0],
      isHardened: isHardened(numbers[0])
    },
    coinType: {
      value: numbers && numbers[1],
      isHardened: isHardened(numbers[1])
    },
    account: {
      value: numbers && numbers[2],
      isHardened: isHardened(numbers[2])
    },
    change: {
      value: numbers && numbers[3],
      isHardened: isHardened(numbers[3])
    },
    index: {
      value: numbers && numbers[4],
      isHardened: isHardened(numbers[4])
    }
  };
};

const BITCOIN_MAINNET_COIN_TYPE = 0;
const BITCOIN_TESTNET_COIN_TYPE = 1;
const BITCOIN_MAIN_NET_ADDRESS_PATTERN = /^(1|3|bc1)/;
const BITCOIN_TEST_NET_ADDRESS_PATTERN = /^(m|n|2|tb1)/;
class PsbtValidator {
  constructor(psbt, network) {
    this.error = null;
    this.tx = psbt;
    this.snapNetwork = network;
    this.psbtHelper = new PsbtHelper(this.tx, network);
  }
  get coinType() {
    return this.snapNetwork === BitcoinNetwork.Main ? BITCOIN_MAINNET_COIN_TYPE : BITCOIN_TESTNET_COIN_TYPE;
  }
  allInputsHaveRawTxHex() {
    const result = this.tx.data.inputs.every(input => !!input.nonWitnessUtxo || !!input.witnessUtxo);
    if (!result) {
      this.error = SnapError.of(PsbtValidateErrors.InputsDataInsufficient);
    }
    return result;
  }
  everyInputMatchesNetwork() {
    const result = this.tx.data.inputs.every(input => {
      if (input.bip32Derivation) {
        return input.bip32Derivation.every(derivation => {
          const {
            coinType
          } = fromHdPathToObj(derivation.path);
          return Number(coinType) === this.coinType;
        });
      }
      return true;
    });
    if (!result) {
      this.error = SnapError.of(PsbtValidateErrors.InputsNetworkNotMatch);
    }
    return result;
  }
  everyOutputMatchesNetwork() {
    const addressPattern = this.snapNetwork === BitcoinNetwork.Main ? BITCOIN_MAIN_NET_ADDRESS_PATTERN : BITCOIN_TEST_NET_ADDRESS_PATTERN;
    const result = this.tx.data.outputs.every((output, index) => {
      if (output.bip32Derivation) {
        return output.bip32Derivation.every(derivation => {
          const {
            coinType
          } = fromHdPathToObj(derivation.path);
          return Number(coinType) === this.coinType;
        });
      } else {
        const address = this.tx.txOutputs[index].address;
        return addressPattern.test(address);
      }
    });
    if (!result) {
      this.error = SnapError.of(PsbtValidateErrors.OutputsNetworkNotMatch);
    }
    return result;
  }
  allInputsBelongToCurrentAccount(accountSigner) {
    const result = this.tx.txInputs.every((_, index) => {
      if (this.tx.data.inputs[index].bip32Derivation) {
        return this.tx.inputHasHDKey(index, accountSigner);
      } else {
        return true;
      }
    });
    if (!result) {
      this.error = SnapError.of(PsbtValidateErrors.InputNotSpendable);
    }
    return result;
  }
  someInputsBelongToCurrentAccount(accountSigner) {
    const result = this.tx.txInputs.some((_, index) => {
      if (this.tx.data.inputs[index].bip32Derivation) {
        return this.tx.inputHasHDKey(index, accountSigner);
      } else {
        return true;
      }
    });
    if (!result) {
      this.error = SnapError.of(PsbtValidateErrors.InputNotSpendable);
    }
    return result;
  }
  changeAddressBelongsToCurrentAccount(accountSigner) {
    const result = this.tx.data.outputs.every((output, index) => {
      if (output.bip32Derivation) {
        return this.tx.outputHasHDKey(index, accountSigner);
      }
      return true;
    });
    if (!result) {
      this.error = SnapError.of(PsbtValidateErrors.ChangeAddressInvalid);
    }
    return result;
  }
  feeUnderThreshold() {
    const result = this.psbtHelper.fee < PsbtValidator.FEE_THRESHOLD;
    if (!result) {
      this.error = SnapError.of(PsbtValidateErrors.FeeTooHigh);
    }
    return result;
  }
  witnessUtxoValueMatchesNoneWitnessOnes() {
    const hasWitnessUtxo = this.tx.data.inputs.some((_, index) => this.tx.getInputType(index) === 'witnesspubkeyhash');
    if (!hasWitnessUtxo) {
      return true;
    }
    const witnessAmount = this.tx.data.inputs.reduce((total, input) => {
      return total + input.witnessUtxo.value;
    }, 0);
    const result = this.psbtHelper.inputAmount === witnessAmount;
    if (!result) {
      this.error = SnapError.of(PsbtValidateErrors.AmountNotMatch);
    }
    return result;
  }
  validate(accountSigner) {
    this.error = null;
    this.allInputsHaveRawTxHex() && this.everyInputMatchesNetwork() && this.everyOutputMatchesNetwork() && this.someInputsBelongToCurrentAccount(accountSigner) &&
    // this.changeAddressBelongsToCurrentAccount(accountSigner) &&
    this.feeUnderThreshold() && this.witnessUtxoValueMatchesNoneWitnessOnes();
    if (this.error) {
      throw this.error;
    }
    return true;
  }
}
PsbtValidator.FEE_THRESHOLD = 10000000;

class Transaction {
  constructor(base64Psbt, network) {
    this.tx = bitcoinjsLib.Psbt.fromBase64(base64Psbt, {
      network: getNetwork(network)
    });
    this.network = network;
  }
  validateTx(accountSigner) {
    const validator = new PsbtValidator(this.tx, this.network);
    return validator.validate(accountSigner);
  }
  extractPsbtJson() {
    const psbtHelper = new PsbtHelper(this.tx, this.network);
    const changeAddress = psbtHelper.changeAddresses;
    const unit = this.network === BitcoinNetwork.Main ? 'sats' : 'tsats';
    const transaction = {
      from: psbtHelper.fromAddresses.join(','),
      to: psbtHelper.toAddresses.join(','),
      value: `${psbtHelper.sendAmount} ${unit}`,
      fee: `${psbtHelper.fee} ${unit}`,
      network: `${this.network}net`
    };
    if (changeAddress.length > 0) {
      return {
        ...transaction,
        changeAddress: changeAddress.join(',')
      };
    }
    return transaction;
  }
  extractPsbtJsonString() {
    return Object.entries(this.extractPsbtJson()).map(([key, value]) => `${key}: ${value}\n`).join('');
  }
  isDefinedSignType(signType) {
    return signType === bitcoinjsLib.Transaction.SIGHASH_DEFAULT || bitcoinjsLib.script.isDefinedHashType(signType);
  }
  signTx(accountSigner, signInputIndex, signType, scriptType) {
    let signHashTypes;
    if (signType && this.isDefinedSignType(signType)) {
      signHashTypes = [signType];
    }
    let signer;
    if (scriptType === ScriptType.P2TR) {
      signer = accountSigner.getTapRootSinger('0/0');
    }
    try {
      if (signInputIndex && !this.isDefinedSignType(signInputIndex)) {
        if (scriptType === ScriptType.P2TR) {
          this.tx.signInput(signInputIndex, signer, signHashTypes);
        } else {
          this.tx.signInputHD(signInputIndex, accountSigner, signHashTypes);
        }
      } else {
        if (scriptType === ScriptType.P2TR) {
          this.tx.signAllInputs(signer, signHashTypes);
        } else {
          this.tx.signAllInputsHD(accountSigner, signHashTypes);
        }
      }
      const txValidator = scriptType === ScriptType.P2TR ? schnorrValidator : validator;
      if (this.tx.validateSignaturesOfAllInputs(txValidator)) {
        this.tx.finalizeAllInputs();
        const txId = this.tx.extractTransaction().getId();
        const txHex = this.tx.extractTransaction().toHex();
        // TODO: sendTransaction to memoPool
        return {
          finally: true,
          txId,
          txHex
        };
      } else {
        return {
          finally: false,
          psbt: this.tx.toBase64()
        };
      }
    } catch (e) {
      throw new Error(`Sign transaction failed...${JSON.stringify(e)}`);
    }
  }
}

bitcoinjsLib.initEccLib(ecc);

async function signPsbt(domain, snap, psbt, network, scriptType, signInputIndex, signType) {
  const tx = new Transaction(psbt, network);
  const txDetails = tx.extractPsbtJson();
  const result = await snap.request({
    method: 'snap_dialog',
    params: {
      type: 'confirmation',
      content: snapsUi.panel([snapsUi.heading('Sign Bitcoin Transaction'), snapsUi.text(`Please verify this ongoing Transaction from ${domain}`), snapsUi.divider(), snapsUi.panel(Object.entries(txDetails).map(([key, value]) => snapsUi.text(`**${key}**:\n ${value}`)))])
    }
  });
  if (result) {
    try {
      const {
        node,
        mfp
      } = await getHDRootNode(snap, getNetwork(network), scriptType);
      const signer = new AccountSigner(node, Buffer.from(mfp, 'hex'));
      tx.validateTx(signer);
      return tx.signTx(signer, signInputIndex, signType, scriptType);
    } catch (e) {
      console.log('sign failed...', e);
    }
    return {
      finally: false,
      txId: '123',
      txHex: '123'
    };
  } else {
    throw SnapError.of(RequestErrors.RejectSign);
  }
}

async function getMasterFingerprint(snap) {
  const {
    mfp
  } = await getHDRootNode(snap, bitcoinjsLib.networks.bitcoin);
  return mfp;
}

async function manageNetwork(origin, snap, action, target) {
  switch (action) {
    case 'get':
      return getPersistedData(snap, "network", "");
    case 'set':
      const result = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: snapsUi.panel([snapsUi.heading('Switch your network'), snapsUi.text(`Do you want to allow ${origin} to switch Bitcoin network to ${target}?`)])
        }
      });
      if (result) {
        await updatePersistedData(snap, "network", target);
        return target;
      } else {
        return "";
      }
    default:
      throw SnapError.of(RequestErrors.ActionNotSupport);
  }
}

const CRYPTO_CURVE$1 = 'secp256k1';
const getHDNode = async (snap, hdPath) => {
  const {
    purpose,
    coinType,
    account,
    change,
    index
  } = parseLightningPath(hdPath);
  const network = coinType.value === '0' ? getNetwork(BitcoinNetwork.Main) : getNetwork(BitcoinNetwork.Test);
  const path = ['m', purpose.value, coinType.value];
  const slip10Node = await snap.request({
    method: 'snap_getBip32Entropy',
    params: {
      path: path,
      curve: CRYPTO_CURVE$1
    }
  });
  const privateKeyBuffer = Buffer.from(trimHexPrefix(slip10Node.privateKey), 'hex');
  const chainCodeBuffer = Buffer.from(trimHexPrefix(slip10Node.chainCode), 'hex');
  // const node: BIP32Interface = bip32.fromPrivateKey(
  //   privateKeyBuffer,
  //   chainCodeBuffer,
  //   network,
  // );
  const node = {};
  //@ts-ignore
  // ignore checking since no function to set depth for node
  node.__DEPTH = slip10Node.depth;
  //@ts-ignore
  // ignore checking since no function to set index for node
  node.__INDEX = slip10Node.index;
  // const pk = node.deriveHardened(1281976168).derive(0).derive(0).publicKey;
  const deriveLNPath = () => {
    let nodeLN = node;
    [account, change, index].forEach(item => {
      if (item.isHardened) {
        nodeLN = nodeLN.deriveHardened(parseInt(item.value));
      }
      if (!item.isHardened) {
        nodeLN = nodeLN.derive(parseInt(item.value));
      }
    });
    return nodeLN;
  };
  return deriveLNPath();
};

async function saveLNDataToSnap(domain, snap, walletId, credential, password) {
  const privateKey = (await getHDNode(snap, LNHdPath)).privateKey.toString('hex');
  const salt = CryptoJs.lib.WordArray.random(16);
  const key = CryptoJs.PBKDF2(privateKey, salt, {
    keySize: 16,
    iterations: 1000
  });
  const iv = CryptoJs.lib.WordArray.random(16);
  const encrypted = CryptoJs.AES.encrypt(credential, key, {
    iv: iv
  });
  const encryptText = salt.toString() + iv.toString() + encrypted.toString();
  const result = await getPersistedData(snap, 'lightning', {});
  const newLightning = {
    ...result,
    [walletId]: {
      credential: encryptText,
      password: password
    }
  };
  await updatePersistedData(snap, 'lightning', newLightning);
}

async function getLNDataFromSnap(domain, snap, {
  key,
  walletId,
  type = 'get'
}) {
  switch (key) {
    case KeyOptions.PubKey:
      return (await getHDNode(snap, LNHdPath)).publicKey.toString('hex');
    case KeyOptions.Password:
      const lightning = await getPersistedData(snap, 'lightning', {});
      return lightning[walletId].password;
    case KeyOptions.Credential:
      const param = {
        get: {
          prompt: 'Access your Lighting wallet credentials',
          description: `Do you want to allow ${domain} to access your Lighting wallet credentials?`
        },
        refresh: {
          prompt: 'Lightning Wallet Data has Expired.',
          description: 'For security purposes, Lightning Wallet data expires after 7 days and needs to be re-authorized.'
        }
      }[type];
      const result = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: snapsUi.panel([snapsUi.heading(param.prompt), snapsUi.text(param.description)])
        }
      });
      if (result) {
        const lightning = await getPersistedData(snap, 'lightning', {});
        const encryptText = lightning[walletId].credential;
        const salt = CryptoJs.enc.Hex.parse(encryptText.substring(0, 32));
        const iv = CryptoJs.enc.Hex.parse(encryptText.substring(32, 64));
        const encrypted = encryptText.substring(64);
        const privateKey = (await getHDNode(snap, LNHdPath)).privateKey.toString('hex');
        const key = CryptoJs.PBKDF2(privateKey, salt, {
          keySize: 512 / 32,
          iterations: 1000
        });
        const credential = CryptoJs.AES.decrypt(encrypted, key, {
          iv: iv
        });
        return credential.toString(CryptoJs.enc.Utf8);
      } else {
        throw SnapError.of(RequestErrors.UserReject);
      }
    default:
      throw SnapError.of(RequestErrors.KeyNotSupported);
  }
}

const formatTime = sec => {
  const hours = Math.floor(sec / 3600);
  const minutes = Math.floor(sec % 3600 / 60);
  if (hours <= 0 && minutes <= 0) {
    return 'Expired';
  }
  return `${hours}H ${minutes}M`;
};
const getBoltField = (invoice, key) => invoice.find(item => item.name === key);
const formatInvoice = invoice => {
  const decodedInvoice = require('light-bolt11-decoder').decode(invoice).sections;
  const expireDatetime = getBoltField(decodedInvoice, 'timestamp').value + getBoltField(decodedInvoice, 'expiry').value;
  return {
    isMainnet: getBoltField(decodedInvoice, 'coin_network').value.bech32 === 'bc',
    amount: hrpToSatoshi(getBoltField(decodedInvoice, 'amount').letters),
    expireTime: expireDatetime - Math.floor(new Date().getTime() / 1000),
    description: getBoltField(decodedInvoice, 'description').value
  };
};
const transferInvoiceContent = invoice => {
  const formattedInvoice = formatInvoice(invoice);
  return {
    network: `Lightning on Bitcoin ${formattedInvoice.isMainnet ? 'mainnet' : 'testnet'}`,
    type: 'send',
    amount: formattedInvoice.amount + ' sats',
    expired_in: formatTime(formattedInvoice.expireTime),
    description: formattedInvoice.description
  };
};

async function signLNInvoice(domain, snap, invoice) {
  const invoiceContent = transferInvoiceContent(invoice);
  const result = await snap.request({
    method: 'snap_dialog',
    params: {
      type: 'confirmation',
      content: snapsUi.panel([snapsUi.heading('Sign Lightning Transaction'), snapsUi.text(`Please verify this ongoing transaction from ${domain}`), snapsUi.divider(), snapsUi.panel(Object.entries(invoiceContent).map(([key, value]) => snapsUi.text(`**${key}**:\n ${value}`)))])
    }
  });
  if (result) {
    const privateKey = (await getHDNode(snap, LNHdPath)).privateKey;
    const signature = bitcoinMessage.sign(invoice, privateKey, true).toString('hex');
    return signature;
  } else {
    throw SnapError.of(RequestErrors.RejectSign);
  }
}

async function getSimpleAddress(origin, snap, network) {
  const networkName = network == bitcoinjsLib.networks.bitcoin ? 'mainnet' : 'testnet';
  const result = await snap.request({
    method: 'snap_dialog',
    params: {
      type: 'confirmation',
      content: snapsUi.panel([snapsUi.heading('Access your account addresses'), snapsUi.text(`Do you want to allow ${origin} to access Bitcoin ${networkName} addresses?`)])
    }
  });
  if (result) {
    const {
      node
    } = await getHDRootNode(snap, network, ScriptType.P2PKH);
    const publicKey = node.publicKey.toString('hex');
    console.log('node public key...', publicKey, node.privateKey.toString('hex'));
    console.log('wif privateKey...', privateKeyToWIF(node.privateKey.toString('hex')));
    return getAddress(network, publicKey);
  } else {
    throw SnapError.of(RequestErrors.RejectKey);
  }
}

// @ts-ignore
globalThis.Buffer = /*#__PURE__*/require('buffer/').Buffer;
const onRpcRequest = async ({
  origin,
  request
}) => {
  await validateRequest(snap, origin, request);
  switch (request.method) {
    case 'btc_getPublicExtendedKey':
      return getExtendedPublicKey(origin, snap, request.params.scriptType, getNetwork(request.params.network));
    case 'btc_getAddress':
      return getSimpleAddress(origin, snap, getNetwork(request.params.network));
    case 'btc_getAllXpubs':
      return getAllXpubs(origin, snap);
    case 'btc_signPsbt':
      const psbt = request.params.psbt;
      return signPsbt(origin, snap, psbt, request.params.network, request.params.scriptType, request.params.signInputIndex, request.params.signType);
    case 'btc_getMasterFingerprint':
      return getMasterFingerprint(snap);
    case 'btc_network':
      return manageNetwork(origin, snap, request.params.action, request.params.network);
    case 'btc_saveLNDataToSnap':
      return saveLNDataToSnap(origin, snap, request.params.walletId, request.params.credential, request.params.password);
    case 'btc_getLNDataFromSnap':
      return getLNDataFromSnap(origin, snap, {
        key: request.params.key,
        ...(request.params.walletId && {
          walletId: request.params.walletId
        }),
        ...(request.params.type && {
          type: request.params.type
        })
      });
    case 'btc_signLNInvoice':
      return signLNInvoice(origin, snap, request.params.invoice);
    default:
      throw SnapError.of(RequestErrors.MethodNotSupport);
  }
};

exports.onRpcRequest = onRpcRequest;
//# sourceMappingURL=btcsnap.cjs.development.js.map
