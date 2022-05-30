setTimeout(() => {
    Java.perform(function() {
    	const ActivityThread = Java.use('android.app.ActivityThread');
    	const PackageManager = Java.use("android.content.pm.PackageManager");
    	const PackageInfo = Java.use("android.content.pm.PackageInfo");

    	const context = ActivityThread.currentApplication().getApplicationContext();
    	
    	const pkgName = context.getPackageName();
    	const pm = context.getPackageManager();

    	const pkgActivites = [];
    	const pkgPermissions = [];
    	const pkgProviders = [];
    	const pkgReceivers = [];
    	const pkgServices = [];
    	const pkgSharedLibs = [];

        const info = pm.getPackageInfo(pkgName, PackageManager.GET_ACTIVITIES.value);
        const perms = pm.getPackageInfo(pkgName, PackageManager.GET_PERMISSIONS.value);
        const prov = pm.getPackageInfo(pkgName, PackageManager.GET_PROVIDERS.value);
        const rcv = pm.getPackageInfo(pkgName, PackageManager.GET_RECEIVERS.value);
        const serv = pm.getPackageInfo(pkgName, PackageManager.GET_SERVICES.value);
        const sharedLibs = pm.getPackageInfo(pkgName, PackageManager.GET_SHARED_LIBRARY_FILES.value).applicationInfo.value.sharedLibraryFiles.value;

        const pkgVersion = pm.getPackageInfo(pkgName, 0);
        const appInfo = pm.getApplicationInfo(pkgName, PackageManager.GET_META_DATA.value);

        const pkgLabel = pm.getApplicationLabel(appInfo).toString();

        for (let i = 0; i < info.activities.value.length; i++) {
        	pkgActivites.push({
        		name: info.activities.value[i].name.value,
        		value: info.activities.value[i].exported.value
        	})
        }

    	for (let i = 0; i < perms.requestedPermissions.value.length; i++) {
            let granted = (perms.requestedPermissionsFlags.value[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED.value) != 0;
     		
    	   	pkgPermissions.push({
        		name: perms.requestedPermissions.value[i],
        		value: granted
        	})
        }

        for (let i = 0; i < prov.providers.value.length; i++) {
        	pkgProviders.push({
        		name: prov.providers.value[i].name.value,
        		value: prov.providers.value[i].exported.value
        	})
        }

        for (let i = 0; i < rcv.receivers.value.length; i++) {
        	pkgReceivers.push({
        		name: rcv.receivers.value[i].name.value,
        		value: rcv.receivers.value[i].exported.value
        	})
        }

        for (let i = 0; i < serv.services.value.length; i++) {
        	pkgServices.push({
        		name: serv.services.value[i].name.value,
        		value: serv.services.value[i].exported.value
        	})
        }

        if (sharedLibs) {
            for (let i = 0; i < sharedLibs.length; i++) {
            	pkgSharedLibs.push({
            		name: sharedLibs[i],
                    value: ''
            	})
            }
        }

    	send({
    		log: 'pkg_info',
            id: pkgName,
    		name: pkgLabel,
    		version: pkgVersion.versionName.value,
    		activities: pkgActivites,
    		permissions: pkgPermissions,
    		providers: pkgProviders,
    		receivers: pkgReceivers,
    		services: pkgServices,
    		sharedLibs: pkgSharedLibs
        })
    });
}, 0);