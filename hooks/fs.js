setTimeout(() => {
    Java.perform(function() {
        const ContextWrapper = Java.use('android.content.ContextWrapper');
        const File = Java.use('java.io.File');

        const openFileOutput = ContextWrapper.openFileOutput.overload('java.lang.String', 'int');

        openFileOutput.implementation = function(path, mode) {
            send({
                log: 'fs',
                path
            })

            return openFileOutput.call(this, path, mode);
        }

        const file_1 = File.$init.overload('java.lang.String');

        file_1.implementation = function(path) {
            send({
                log: 'fs',
                path
            })

            return file_1.call(this, path);
        }

        const file_2 = File.$init.overload('java.net.URI');

        file_2.implementation = function(path) {
            send({
                log: 'fs',
                path: path.toString()
            })

            return file_2.call(this, path);
        }

        const file_3 = File.$init.overload('java.io.File', 'java.lang.String');

        file_3.implementation = function(parent, child) {
            send({
                log: 'fs',
                path: parent.toString() + "/" + child
            })

            return file_3.call(this, parent, child);
        }

        const file_4 = File.$init.overload('java.lang.String', 'int');

        file_4.implementation = function(path, mode) {
            send({
                log: 'fs',
                path: path.toString()
            })

            return file_4.call(this, path, mode);
        }

        const file_5 = File.$init.overload('java.lang.String', 'java.lang.String');

        file_5.implementation = function(parent, child) {
            send({
                log: 'fs',
                path: parent + '/' + child
            })

            return file_5.call(this, parent, child);
        }
    });
}, 0);