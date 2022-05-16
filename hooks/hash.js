Java.perform(function() {
    function b2s(array) {
        let result = "";
        for (let i = 0; i < array.length; i++) {
            result += String.fromCharCode(modulus(array[i], 256));
        }
        return result;
    }

    function modulus(x, n) {
        return ((x % n) + n) % n;
    }

    function encodeHex(byteArray) {
        const HexClass = Java.use('org.apache.commons.codec.binary.Hex');
        const StringClass = Java.use('java.lang.String');
        const hexChars = HexClass.encodeHex(byteArray);
        return StringClass.$new(hexChars).toString();
    }

    const MessageDigest = Java.use('java.security.MessageDigest');

    const digest_1 = MessageDigest.digest.overload('[B');

    digest_1.implementation = function(byte_array) {
        const algo = this.getAlgorithm();
        const hash = digest_1.call(this, byte_array);

        let hashStr = encodeHex(hash);

        send({
            log: 'hash',
            algo,
            input: b2s(byte_array),
            output: hashStr
        })

        return hash;
    }
});