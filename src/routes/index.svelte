<script lang="ts">
	import { onMount } from "svelte";
	import { goto } from "$app/navigation";
	
	import Omni from '$lib/omni';

	let devices = [];

	let selectedDevice: string = "";
	let timerSeconds: number = 0;

	const getDeviceApplications = async (): Promise<void> => {
		await goto(`/applications?device=${selectedDevice}`);
	}

	const updateDevices = async (): Promise<void> => {
		if (timerSeconds == 0) {
			let res = await Omni.getDevices();

			if (res.success) {
				devices = res.data;
			}

			timerSeconds = 5;
		} else {
			timerSeconds--;
		}

		setTimeout(updateDevices, 1000);
	}

	onMount(() => {
		updateDevices();
	})
</script>

<svelte:head>
	<title>frida-omni</title>
</svelte:head>

<section class="p-8 flex flex-col justify-center min-h-0 h-screen">
	<div class="flex flex-col items-center text-white">
		<a href="/">
			<svg class="w-16 h-16" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>
		</a>

		<h1 class="font-bold text-4xl">frida-omni</h1>
	</div>

	<div class="w-full flex flex-col items-center my-4">
		{#if devices.length}
			<div class="text-white text-center mb-2">
				<div class="text-lg">{devices.length} device(s) found</div>
				<p class="opacity-50 text-sm">Refreshing in {timerSeconds}s.</p>
			</div>
			<ul class="w-full max-w-xl space-y-4 max-h-96 overflow-y-auto">
				{#each devices as d (d.id)}
					<li class="rounded border border-white/10 hover:cursor-pointer hover:border-teal-600" on:click={(e) => selectedDevice = d.id}>
						<div class="flex relative">
							<div class="w-20 flex items-center justify-center bg-white/5 text-white">
								<svg class="w-16 h-20" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"></path></svg>
							</div>
							<div class="p-4 text-white w-full">
								<h3 class="font-semibold text-2xl">
									{d.name}
								</h3>
								<h4 class="opacity-50">{d.id}</h4>
							</div>
							{#if selectedDevice == d.id}
								<div class="absolute right-0 h-full mr-2 flex items-center text-teal-600">
									<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
								</div>
							{/if}
						</div>
					</li>
				{/each}
			</ul>
		{:else}
			<div class="text-white text-center">
				<p class="text-lg">No devices connected</p>
				<p class="opacity-50 text-sm">Refreshing in {timerSeconds}s.</p>
			</div>
		{/if}
	</div>

	{#if selectedDevice != ""}
		<div class="p-2 w-full text-center">
			<button class="rounded-full bg-teal-600 hover:bg-teal-700 px-4 py-1 font-bold text-white" on:click={getDeviceApplications}>
				Next
			</button>
		</div>
	{/if}
</section>