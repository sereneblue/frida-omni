Java.perform(function() {
    const JavaString = Java.use('java.lang.String');

    function encodeHex(byteArray) {
        const HexClass = Java.use('org.apache.commons.codec.binary.Hex');
        const hexChars = HexClass.encodeHex(byteArray);
        return JavaString.$new(hexChars).toString();
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
            input: encodeHex(byte_array),
            output: hashStr
        })

        return hash;
    }
});