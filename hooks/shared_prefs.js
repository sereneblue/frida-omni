Java.perform(function() {
    const ContextWrapper = Java.use('android.content.ContextWrapper');
    const Editor = Java.use('android.content.SharedPreferences$Editor');
    const SharedPreferences = Java.use('android.content.SharedPreferences');

    const getSharedPreferences = ContextWrapper.getSharedPreferences.overload('java.lang.String', 'int');

    function getMode(mode) {
        if (mode == 0) {
            return "MODE_PRIVATE";
        } else if (mode == 1) {
            return "MODE_WORLD_READABLE";
        } else if (mode == 2) {
            return "MODE_WORLD_WRITEABLE";
        } else if (mode == 32768) {
            return "MODE_APPEND";
        }
    }

    getSharedPreferences.implementation = function (file, mode) {
        send({    
            log: 'shared_prefs',
            method: 'getSharedPreferences',
            value: `File: ${file.toString()}, Mode: ${getMode(mode)}`
        })

        return getSharedPreferences.call(this, file, mode);
    }

    const putBoolean = Editor.putBoolean.overload('java.lang.String', 'boolean');

    putBoolean.implementation = function (key, value) {        
        send({
            log: 'shared_prefs',
            method: 'putBoolean',
            value: `${key}=${value}`
        })

        return putBoolean.call(this, key, value);
    }

    const putFloat = Editor.putFloat.overload('java.lang.String', 'float');

    putFloat.implementation = function (key, value) {
        send({
            log: 'shared_prefs',
            method: 'putFloat',
            value: `${key}=${value}`
        })

        return putFloat.call(this, key, value);
    }

    const putInt = Editor.putInt.overload('java.lang.String', 'int');

    putInt.implementation = function (key, value) {
        send({
            log: 'shared_prefs',
            method: 'putInt',
            value: `${key}=${value}`
        })

        return putInt.call(this, key, value);
    }

    const putLong = Editor.putLong.overload('java.lang.String', 'long');

    putLong.implementation = function (key, value) {
        send({
            log: 'shared_prefs',
            method: 'putLong',
            value: `${key}=${value}`
        })

        return putLong.call(this, key, value);
    }

    const putString = Editor.putString.overload('java.lang.String', 'java.lang.String');

    putString.implementation = function (key, value) {
        send({
            log: 'shared_prefs',
            method: 'putString',
            value: `${key}=${value}`
        })

        return putString.call(this, key, value);
    }

    const putStringSet = Editor.putStringSet.overload('java.lang.String', 'java.util.Set');

    putStringSet.implementation = function (key, values) {
        send({
            log: 'shared_prefs',
            method: 'putStringSet',
            value: `${key}=${values.toArray()}`
        })

        return putStringSet.call(this, key, values);
    }

    const getBoolean = SharedPreferences.getBoolean.overload('java.lang.String', 'boolean');

    getBoolean.implementation = function (key, value) {
        const val = getBoolean.call(this, key, value);

        send({
            log: 'shared_prefs',
            method: 'getBoolean',
            value: `${key}: default=${value} value=${val}`
        })

        return val;
    }

    const getFloat = SharedPreferences.getFloat.overload('java.lang.String', 'float');

    getFloat.implementation = function (key, value) {
        const val = getFloat.call(this, key, value);

        send({
            log: 'shared_prefs',
            method: 'getFloat',
            value: `${key}: default=${value} value=${val}`
        })

        return val;
    }

    const getInt = SharedPreferences.getInt.overload('java.lang.String', 'int');

    getInt.implementation = function (key, value) {
        const val = getInt.call(this, key, value);

        send({
            log: 'shared_prefs',
            method: 'getInt',
            value: `${key}: default=${value} value=${val}`
        })

        return val;
    }

    const getLong = SharedPreferences.getLong.overload('java.lang.String', 'long');

    getLong.implementation = function (key, value) {
        const val = getLong.call(this, key, value);

        send({
            log: 'shared_prefs',
            method: 'getLong',
            value: `${key}: default=${value} value=${val}`
        })

        return val;
    }

    const getString = SharedPreferences.getString.overload('java.lang.String', 'java.lang.String');

    getString.implementation = function (key, value) {
        const val = getString.call(this, key, value);

        send({
            log: 'shared_prefs',
            method: 'getString',
            value: `${key}: default=${value} value=${val}`
        })

        return val;
    }

    const getStringSet = SharedPreferences.getStringSet.overload('java.lang.String', 'java.util.Set');

    getStringSet.implementation = function (key, values) {
        const val = getStringSet.call(this, key, values);

        send({
            log: 'shared_prefs',
            method: 'getStringSet',
            value: `${key}: default=${values.toArray()} value=${val.toArray()}`
        })

        return val;
    }
});