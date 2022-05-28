<script context="module">
  export function load({ url }) {
    const deviceId = url.searchParams.get('device') || '';
    const appId = url.searchParams.get('app') || '';

    return {
      props: {
        deviceId,
        appId
      }
    };
  }
</script>

<script lang="ts">
	import { onMount } from "svelte";
	import { goto } from "$app/navigation";
	import { page } from "$app/stores";
	import { 
		CryptoView,
		FSView,
		HashView, 
		HttpView, 
		PackageInfoView,
		SharedPrefsView,
		SQLiteView, 
		TabBadge 
	} from "$lib/components/index.ts";
	
	import Omni from '$lib/omni';

	export let appId: string;
	export let deviceId: string;

	const enum Tab {
		PackageInfo,
		SharedPrefs,
		Crypto,
		Hash,
		SQLite,
		HTTP,
		FileSystem
	}

	let selectedTab: Tab = Tab.PackageInfo;
	let appName = '';
	let appVersion = '';
	let appRunning = false;
	let appActionLoaded = false;
	let timerSeconds: number = 0;
	let logTimeout: number = 0;
	let logData = {
		totals: {
			crypto: 0,
			fs: 0,
			hash: 0,
			http: 0,
			sqlite: 0,
			shared_prefs: 0
		},
		logs: {
			pkg_info: [],
			crypto: [],
			fs: [],
			hash: [],
			http: [],
			sqlite: [],
			shared_prefs: []
		}
	};

	let queryData = {
		search: {}
	}

	$: {
		appId = $page.url.searchParams.get('app');
		deviceId = $page.url.searchParams.get('device');
	}

	const omni = new Omni();

	const action = async (action: string): Promise<void> => {
		if (!appActionLoaded) {
			appActionLoaded = true;
	
			try {
				let res = await omni.postAction(deviceId, appId, action);

				if (action == 'download') {
					omni.saveFile(res.data);
				}
			} catch (e) {} finally {
				appActionLoaded = false;
			}
		}
	}

	const getLogs = async (e: Event): Promise<void> => {
		queryData.search[e.detail.type] = e.detail.value;

		timerSeconds = 0;
		clearTimeout(logTimeout);
		await updateLogData();
	}

	const updateLogData = async (): Promise<void> => {
		if (timerSeconds == 0) {
			let res = await omni.getLogData(deviceId, appId, queryData);

			if (res.success) {
				logData = res.data;

				appName = res.data.meta.name;
				appRunning = res.data.meta.running;
				appVersion = logData.logs.pkg_info.version;
			} else {
				if (res.message == 'device_not_found') {
					await goto('/');
				} else if (res.message == 'app_not_found') {
					await goto('/applications?device=' + deviceId);
				}
			}

			timerSeconds = 10;
		} else {
			timerSeconds--;
		}

		logTimeout = setTimeout(updateLogData, 1000);
	}

	onMount(async () => {
		if (appId == "") {
			await goto('/applications?device=' + deviceId);
		} else if (deviceId == "") {
			await goto('/');
		}
		
		updateLogData();
	})
</script>

<svelte:head>
	<title>Dashboard | frida-omni</title>
</svelte:head>

<section class="px-8 py-4 flex flex-col min-h-0 h-screen">
	<div class="flex items-center justify-between text-white">
		<div>
			<span class="font-bold text-2xl mr-2">{appName}</span>
			<span class="opacity-50">{appId}</span>
		</div>
		<div class="flex gap-x-1">
			<button class="flex items-center gap-x-1 bg-transparent border border-gray-600 text-xs text-white rounded px-2 p-1" on:click={e => goto('/') }>
				Devices
			</button>
			<button class="flex items-center gap-x-1 bg-transparent border border-gray-600 text-xs text-white rounded px-2 p-1" on:click={e => goto('/applications?device=' + deviceId) }>
				Apps
			</button>
		</div>
	</div>
	<div class="flex items-center bg-white/5 justify-between text-white my-3 rounded">
		<div class="flex">
			<div on:click={e => selectedTab = Tab.PackageInfo} class={ selectedTab == Tab.PackageInfo ? 'tab active group' : 'tab' }>
				Package Info
			</div>
			<div on:click={e => selectedTab = Tab.SharedPrefs} class={ selectedTab == Tab.SharedPrefs ? 'tab active group' : 'tab' }>
				Shared Preferences
				<TabBadge count={logData.totals.shared_prefs} />
			</div>
			<div on:click={e => selectedTab = Tab.Crypto} class={ selectedTab == Tab.Crypto ? 'tab active group' : 'tab' }>
				Crypto
				<TabBadge count={logData.totals.crypto} />
			</div>
			<div on:click={e => selectedTab = Tab.Hash} class={ selectedTab == Tab.Hash ? 'tab active group' : 'tab' }>
				Hash
				<TabBadge count={logData.totals.hash} />
			</div>
			<div on:click={e => selectedTab = Tab.SQLite} class={ selectedTab == Tab.SQLite ? 'tab active group' : 'tab' }>
				SQLite
				<TabBadge count={logData.totals.sqlite} />
			</div>
			<div on:click={e => selectedTab = Tab.HTTP} class={ selectedTab == Tab.HTTP ? 'tab active group' : 'tab' }>
				HTTP
				<TabBadge count={logData.totals.http} />
			</div>
			<div on:click={e => selectedTab = Tab.FileSystem} class={ selectedTab == Tab.FileSystem ? 'tab active group' : 'tab' }>
				File System
				<TabBadge count={logData.totals.fs} />
			</div>
		</div>
		<div class="flex mr-2">
			{#if appRunning == false}
				<button class="hover:text-teal-600 p-1 disabled:opacity-25 disabled:hover:text-white disabled:cursor-none" title="Start" disabled={appActionLoaded} on:click={e => action('start')}>
					<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
				</button>
			{:else}
				<button class="hover:text-teal-600 p-1 disabled:opacity-25 disabled:hover:text-white disabled:cursor-none" title="Download logs" disabled={appActionLoaded} on:click={e => action('download')}>
					<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
				</button>
				<button class="hover:text-teal-600 p-1 disabled:opacity-25 disabled:hover:text-white disabled:cursor-none" title="Restart" disabled={appActionLoaded} on:click={e => action('start')}>
					<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
				</button>
				<button class="hover:text-teal-600 p-1 disabled:opacity-25 disabled:hover:text-white disabled:cursor-none" title="Stop" disabled={appActionLoaded} on:click={e => action('stop')}>
					<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
				</button>
			{/if}
		</div>
	</div>

	<div class="pb-8">
		{#if selectedTab == Tab.PackageInfo}
			<PackageInfoView data={logData.logs.pkg_info} />
		{:else if selectedTab == Tab.Crypto}
			<CryptoView data={logData.logs.crypto} query={queryData.search.crypto} on:search={getLogs}  />
		{:else if selectedTab == Tab.FileSystem}
			<FSView data={logData.logs.fs} query={queryData.search.fs} on:search={getLogs} />
		{:else if selectedTab == Tab.Hash}
			<HashView data={logData.logs.hash} query={queryData.search.hash} on:search={getLogs}  />
		{:else if selectedTab == Tab.HTTP}
			<HttpView data={logData.logs.http} query={queryData.search.http} on:search={getLogs} />
		{:else if selectedTab == Tab.SharedPrefs}
			<SharedPrefsView data={logData.logs.shared_prefs} />
		{:else if selectedTab == Tab.SQLite}
			<SQLiteView data={logData.logs.sqlite} query={queryData.search.sqlite} on:search={getLogs} />
		{/if}
	</div>

</section>

<style lang="postcss">
	.tab {
		@apply px-2 py-1 opacity-50 flex items-center gap-x-1;
	}

	.tab:hover {
		@apply bg-white/5 cursor-pointer;
	}

	.tab.active {
		@apply opacity-100 border-b-2 border-teal-600 font-bold;
	}
</style>