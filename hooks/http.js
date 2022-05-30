setTimeout(() => {
    Java.perform(function() {
        Java.use('javax.net.ssl.HttpsURLConnection').$init.overload('java.net.URL').implementation = function(url) {
            send({
                log: 'http',
                url: url.toString()
            })

            return this.$init(url);
        };

        Java.use('java.net.HttpURLConnection').$init.overload('java.net.URL').implementation = function(url) {
            send({
                log: 'http',
                url: url.toString()
            })

            return this.$init(url);
        };

        try {
            const AndroidOkHttpRequestBuilder = Java.use("com.android.okhttp.Request$Builder");

            const android_url_1 = AndroidOkHttpRequestBuilder.url.overload("com.android.okhttp.HttpUrl");
            const android_url_2 = AndroidOkHttpRequestBuilder.url.overload("java.lang.String");
            const android_url_3 = AndroidOkHttpRequestBuilder.url.overload("java.net.URL");

            android_url_1.implementation = function (url) {
                send({
                    log: 'http',
                    url: url.toString()
                })

                return android_url_1.call(this, url);
            }

            android_url_2.implementation = function (url) {
                send({
                    log: 'http',
                    url: url
                })

                return android_url_2.call(this, url);
            }

            android_url_3.implementation = function (url) {
                send({
                    log: 'http',
                    url: url.toString()
                })

                return android_url_3.call(this, url);
            }
        } catch (e) {}

        try {
            const SquareRequestBuilder = Java.use("com.squareup.okhttp.Request$Builder");

            const square_url_1 = SquareRequestBuilder.url.overload("com.squareup.okhttp.HttpUrl");
            const square_url_2 = SquareRequestBuilder.url.overload("java.lang.String");
            const square_url_3 = SquareRequestBuilder.url.overload("java.net.URL");

            square_url_1.implementation = function (url) {
                send({
                    log: 'http',
                    url: url.toString()
                })

                return square_url_1.call(this, url);
            }

            square_url_2.implementation = function (url) {
                send({
                    log: 'http',
                    url: url
                })

                return square_url_2.call(this, url);
            }

            square_url_3.implementation = function (url) {
                send({
                    log: 'http',
                    url: url.toString()
                })

                return square_url_3.call(this, url);
            }
        } catch (e) {}
    });
}, 0);