<script lang="ts">
	import { createEventDispatcher } from 'svelte';

	export let search;
	
	const dispatch = createEventDispatcher();	

	let timer;

	const debounce = value => {
		clearTimeout(timer);
		timer = setTimeout(() => {
			dispatch('search', value);
		}, 350);
	}
</script>

<input 
	on:input={e => debounce(e.target.value)}
	class="w-full px-2 py-1 border border-gray-600 bg-transparent rounded text-white"
	placeholder="Search logs..."
	bind:value={search}
	type="text">