setTimeout(() => {
    Java.perform(function() {
    	const SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        const ContentWrapper = Java.use('android.content.ContextWrapper');

        const execSQL_1 = SQLiteDatabase.execSQL.overload('java.lang.String');

        execSQL_1.implementation = function(statement) {
            send({
                log: 'sqlite',
                db: this.getPath(),
                method: 'execSQL',
                value: statement
            })

            return execSQL_1.call(this, statement);
        }

        const execSQL_2 = SQLiteDatabase.execSQL.overload('java.lang.String', '[Ljava.lang.Object;');

        execSQL_2.implementation = function(statement, bindArgs) {
            send({
                log: 'sqlite',
                db: this.getPath(),
                method: 'execSQL',
                value: statement + bindArgs.toString()
            })

            return execSQL_2.call(this, statement, bindArgs);
        }

        const insert = SQLiteDatabase.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues');

        insert.implementation = function(table, nullColumnHack, values) {
            send({
                log: 'sqlite',
                db: this.getPath(),
                method: 'insert',
                value: `INSERT INTO ${table} VALUES(${values});`
            })

            return insert.call(this, table, nullColumnHack, values);
        }

        const rawQuery_1 = SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;');

        rawQuery_1.implementation = function(sql, selectionArgs) {
            let statement = sql;

            if (selectionArgs) {
                statement = sql.split('?').map(function (value, index) { return selectionArgs[index] ? value + selectionArgs[index] : (value ? value : '') }).join("");
            }

            send({
                log: 'sqlite',
                db: this.getPath(),
                method: 'rawQuery',
                value: statement
            })

            return rawQuery_1.call(this, sql, selectionArgs);
        }

        const rawQuery_2 = SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;', 'android.os.CancellationSignal');

        rawQuery_2.implementation = function(sql, selectionArgs, cancellationSignal) {
            let statement = sql;

            if (selectionArgs) {
                statement = sql.split('?').map(function (value, index) { return selectionArgs[index] ? value + selectionArgs[index] : (value ? value : '') }).join("");
            }

            send({
                log: 'sqlite',
                db: this.getPath(),
                method: 'rawQuery',
                value: statement
            })

            return rawQuery_2.call(this, sql, selectionArgs, cancellationSignal);
        }

        const update = SQLiteDatabase.update.overload('java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;');

        update.implementation = function(table, values, whereClause, whereArgs) {
            let clause = whereClause;

            if (whereArgs) {
                clause = whereClause.split('?').map(function (value, index) { return whereArgs[index] ? value + whereArgs[index] : (value ? value : '') }).join("");
            }

            send({
                log: 'sqlite',
                db: this.getPath(),
                method: 'update',
                value: `UPDATE ${table} SET (${values}) WHERE ${clause};`
            })

            return update.call(this, table, values, whereClause, whereArgs);
        }

        const query = ContentWrapper.getDatabasePath.overload('java.lang.String');

        query.implementation = function(path) {
            send({
                log: 'sqlite',
                db: path,
                method: 'query',
                value: path
            })

            return query.call(this, path);
        }

        const getDatabasePath = ContentWrapper.getDatabasePath.overload('java.lang.String');

        getDatabasePath.implementation = function(path) {
            send({
                log: 'sqlite',
                db: '',
                method: 'getDatabasePath',
                value: path
            })

            return getDatabasePath.call(this, path);
        }

        // sqlcipher

        try {
            const SQLCipher_SQLiteDatabase = Java.use('net.sqlcipher.database.SQLiteDatabase');
            const SQLiteOpenHelper = Java.use('net.sqlcipher.database.SQLiteOpenHelper');

            const execSQL_3 = SQLCipher_SQLiteDatabase.execSQL.overload('java.lang.String', '[Ljava.lang.Object;');

            execSQL_3.implementation = function(statement, bindArgs) {
                send({
                    log: 'sqlite',
                    db: SQLCipher_SQLiteDatabase.getPath.call(this),
                    method: 'execSQL',
                    value: statement + bindArgs.toString()
                })

                return execSQL_3.call(this, statement, bindArgs);
            }

            const rawQuery_3 = SQLCipher_SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;', 'android.os.CancellationSignal');

            rawQuery_3.implementation = function(sql, selectionArgs, cancellationSignal) {
                let statement = sql;

                if (selectionArgs) {
                    statement = sql.split('?').map(function (value, index) { return selectionArgs[index] ? value + selectionArgs[index] : (value ? value : '') }).join("");
                }

                send({
                    log: 'sqlite',
                    db: this.getPath(),
                    method: 'rawQuery',
                    value: statement
                })

                return rawQuery_3.call(this, sql, selectionArgs, cancellationSignal);
            }

            const getWritableDatabase = SQLiteOpenHelper.getWritableDatabase.overload('java.lang.String');

            getWritableDatabase.implementation = function (password) {
                let syncDb = getWritableDatabase.call(this, password);

                send({
                    log: 'sqlite',
                    db: this.mName.value,
                    method: 'getWritableDatabase',
                    value: password
                })

                return syncDb;
            }
        } catch (e) {}
    });
}, 0);