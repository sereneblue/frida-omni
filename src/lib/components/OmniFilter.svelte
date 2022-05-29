<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { fade } from "svelte/transition";

	export let filters = [];

	const dispatch = createEventDispatcher();

	let open = false;
	let timer;

	const debounce = target => {
		clearTimeout(timer);
		timer = setTimeout(() => {
			dispatch('filter', { id: target.value, checked: target.checked });
		}, 350);
	}

	const handleClickOutside = (node: Node): object => {
		const handleClick = (event: Event) => {
			let path = event.composedPath();

			if (!path.includes(node)) {
				open = false;
			}
		};

		setTimeout(() => {
			document.addEventListener("click", handleClick);
		}, 10);

		return {
			destroy() {
				document.removeEventListener("click", handleClick);
			},
		};
	};
</script>

<div class="relative inline-block text-left">
	<div class="h-full">
		<button type="button" class="px-2 py-2 border border-gray-600 bg-transparent rounded text-white" aria-expanded="false" aria-haspopup="true" title="Filter" on:click={e => open = !open}>
	    	<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"></path></svg>
		</button>
	</div>

	{#if open}
		<div
	     transition:fade={{ duration: 150 }}
    	 use:handleClickOutside
		 class="origin-top-right absolute right-0 mt-2 rounded-md shadow-2xl bg-gray-700 ring-1 ring-black ring-opacity-5 focus:outline-none text-sm text-white border border-gray-600" role="menu" aria-orientation="vertical" tabindex="-1">
			<div class="py-1" role="none">
				{#each filters as f}
					<label class="flex items-center gap-x-2 hover:bg-white/5 hover:cursor-pointer block px-2 py-1.5">
						<input 
							on:change={e => debounce(e.target)}
							type="checkbox" value={f.value} bind:checked={f.enabled}>
						<span class="whitespace-nowrap">{f.text}</span>
					</label>
				{/each}
			</div>
		</div>
	{/if}
</div>