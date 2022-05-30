setTimeout(() => {
    Java.perform(function() {
        const JavaString = Java.use('java.lang.String');
        const Cipher = Java.use('javax.crypto.Cipher');
        const SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        const PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec');
        const IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
        const SecureRandom = Java.use('java.security.SecureRandom');

        function encodeHex(byteArray) {
            const HexClass = Java.use('org.apache.commons.codec.binary.Hex');
            const hexChars = HexClass.encodeHex(byteArray);
            return JavaString.$new(hexChars).toString();
        }

        function getOpMode(opMode) {
            if (opMode == 1) {
                return "ENCRYPT_MODE";
            } else if (opMode == 2) {
                return "DECRYPT_MODE";
            } else if (opMode == 3) {
                return "WRAP_MODE";
            } else if (opMode == 4) {
                return "UNWRAP_MODE";
            }
        }

        const cipher_init_1 = Cipher.init.overload("int", "java.security.Key", "java.security.AlgorithmParameters");
        const cipher_init_2 = Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec");

        cipher_init_1.implementation = function (opmode, key, params) {
            send({
                log: 'crypto',
                method: 'init',
                params: JSON.stringify({
                    opmode: getOpMode(opmode),
                    key: encodeHex(key.getEncoded()),
                    params: params.toString()
                })
            })

            return cipher_init_1.call(this, opmode, key, params);
        }

        cipher_init_2.implementation = function (opmode, key, params) {
            send({
                log: 'crypto',
                method: 'init',
                params: JSON.stringify({
                    opmode: getOpMode(opmode),
                    key: encodeHex(key.getEncoded()),
                    params: encodeHex(Java.cast(params, IvParameterSpec).getIV())
                })
            })

            return cipher_init_2.call(this, opmode, key, params);
        }

        const doFinal = Cipher.doFinal.overload('[B');

        doFinal.implementation = function(byte_array) {
            const params = this.getParameters();
            const paramStr = params == null ? '' : params.toString();

            const result = doFinal.call(this, byte_array);

            send({
                log: 'crypto',
                method: 'doFinal',
                params: JSON.stringify({
                    params: paramStr,
                    input: encodeHex(byte_array),
                    output: encodeHex(result)
                })
            })

            return result;
        }

        const secr_1 = SecretKeySpec.$init.overload('[B', 'int', 'int', 'java.lang.String');
        const secr_2 = SecretKeySpec.$init.overload('[B', 'java.lang.String');

        secr_1.implementation = function(byte_array, offset, len, algo) {
            send({
                log: 'crypto',
                method: 'SecretKeySpec',
                params: JSON.stringify({
                    key: encodeHex(byte_array),
                    offset,
                    len,
                    algo
                })
            })

            return secr_1.call(this, byte_array, offset, len, algo);
        }

        secr_2.implementation = function(byte_array, algo) {
            send({
                log: 'crypto',
                method: 'SecretKeySpec',
                params: JSON.stringify({
                    key: encodeHex(byte_array),
                    algo
                })
            })

            return secr_2.call(this, byte_array, algo);
        }

        const ivparam_1 = IvParameterSpec.$init.overload('[B');
        const ivparam_2 = IvParameterSpec.$init.overload('[B', 'int', 'int');

        ivparam_1.implementation = function(byte_array) {
            send({
                log: 'crypto',
                method: 'IvParameterSpec',
                params: JSON.stringify({
                    iv: encodeHex(byte_array),
                })
            })

            return ivparam_1.call(this, byte_array);
        }

        ivparam_2.implementation = function(byte_array, offset, len) {
            send({
                log: 'crypto',
                method: 'IvParameterSpec',
                params: JSON.stringify({
                    iv: encodeHex(byte_array),
                    offset,
                    len
                })
            })

            return ivparam_2.call(this, byte_array, offset, len);
        }

        const pbe_1 = PBEKeySpec.$init.overload('[C');
        const pbe_2 = PBEKeySpec.$init.overload('[C', '[B', 'int');
        const pbe_3 = PBEKeySpec.$init.overload('[C', '[B', 'int', 'int');

        pbe_1.implementation = function(password) {
            send({
                log: 'crypto',
                method: 'PBEKeySpec',
                params: JSON.stringify({
                    password: JavaString.$new(password).toString(),
                })
            })

            return pbe_1.call(this, password);
        }

        pbe_2.implementation = function(password, salt, iterationCount) {
            send({
                log: 'crypto',
                method: 'PBEKeySpec',
                params: JSON.stringify({
                    password: JavaString.$new(password).toString(),
                    salt: encodeHex(salt),
                    iterationCount
                })
            })

            return pbe_2.call(this, password, salt, iterationCount);
        }

        pbe_3.implementation = function(password, salt, iterationCount, keyLength) {
            send({
                log: 'crypto',
                method: 'PBEKeySpec',
                params: JSON.stringify({
                    password: JavaString.$new(password).toString(),
                    salt: encodeHex(salt),
                    iterationCount,
                    keyLength
                })
            })

            return pbe_3.call(this, password, salt, iterationCount, keyLength);
        }

        const setSeed_1 = SecureRandom.$init.overload('[B');
        const setSeed_2 = SecureRandom.setSeed.overload('[B');
        const setSeed_3 = SecureRandom.setSeed.overload('long');

        setSeed_1.implementation = function(seed) {
            send({
                log: 'crypto',
                method: 'SecureRandom',
                params: encodeHex(seed)
            })

            return setSeed_1.call(this, seed);
        }

        setSeed_2.implementation = function(seed) {
            send({
                log: 'crypto',
                method: 'SecureRandom (bytes)',
                params: encodeHex(seed)
            })

            return setSeed_2.call(this, seed);
        }

        setSeed_3.implementation = function(seed) {
            send({
                log: 'crypto',
                method: 'SecureRandom (long)',
                params: seed
            })

            return setSeed_3.call(this, seed);
        }
    });
}, 0)