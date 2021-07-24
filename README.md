# Web3TransactionSignVerify


Web-3 references:

- sendSignedTx (sign)
  
  - https://github.com/ChainSafe/web3.js/blob/1ed3c68b5e99e1b5e893068ff0b2d1c86a98d1c1/packages/web3-core-method/src/index.js#L753

- Multiple ways to sign using privateKey Vs Accont:

   1. private key should be prefixed with '0x'

   2. web3.eth.accounts.recover API is changed

    ```js
    const signTest = async function(){

    // Using eth.sign()

    let accounts = await web3.eth.getAccounts();
    let msg = "Some data"

    let prefix = "\x19Ethereum Signed Message:\n" + msg.length
    let msgHash1 = web3.utils.sha3(prefix+msg)

    let sig1 = await web3.eth.sign(msg, accounts[0]);


    // Using eth.accounts.sign() - returns an object

    let privateKey = "0xc87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3"

    let sigObj = await web3.eth.accounts.sign(msg, privateKey)
    let msgHash2 = sigObj.messageHash;

    let sig2 = sigObj.signature;


    let whoSigned1 = await web3.eth.accounts.recover(msg, sig1)
    let whoSigned2 = await web3.eth.accounts.recover(sigObj)

   }
```


- Web3.js : eth.sign() vs eth.accounts.sign()
  - 
  - https://ethereum.stackexchange.com/questions/35425/web3-js-eth-sign-vs-eth-accounts-sign-producing-different-signatures?rq=1


- Recover and verify signed-data-hash and signature:
 
 ```js
 /**
   * @dev Recover signer address from a message by using their signature
   * @param hash bytes32 message, the hash is the signed message. What is recovered is the signer address.
   * @param signature bytes signature, the signature is generated using web3.eth.sign()
   */
  function recover(bytes32 hash, bytes signature)
    internal
    pure
    returns (address)
  {
    bytes32 r;
    bytes32 s;
    uint8 v;

    // Check the signature length
    if (signature.length != 65) {
      return (address(0));
    }

    // Divide the signature in r, s and v variables with inline assembly.
    assembly {
      r := mload(add(signature, 0x20))
      s := mload(add(signature, 0x40))
      v := byte(0, mload(add(signature, 0x60)))
    }

    // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
    if (v < 27) {
      v += 27;
    }

    // If the version is correct return the signer address
    if (v != 27 && v != 28) {
      return (address(0));
    } else {
      // solium-disable-next-line arg-overflow
      return ecrecover(hash, v, r, s);
    }
  }

  /**
    * toEthSignedMessageHash
    * @dev prefix a bytes32 value with "\x19Ethereum Signed Message:"
    * and hash the result
    */
  function toEthSignedMessageHash(bytes32 hash)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(
      abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
    );
  }  
```


