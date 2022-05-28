<script lang="ts">
	import OmniTable from "./OmniTable.svelte";
	import { createEventDispatcher } from 'svelte';

	const dispatch = createEventDispatcher();

	export let data = [];
	export let query = "";

	const headers = ["Timestamp", "Hash", "Input", "Output"];
	const render = [
		{
			fn: (data) => data.timestamp,
			clipboard: false,
		},
		{
			fn: (data) => data.algo,
			clipboard: false,
		},
		{
			fn: (data) => data.input,
			clipboard: true,
		},
		{
			fn: (data) => data.output,
			clipboard: true,
		},
	]
</script>

<div>
	<OmniTable {headers} {data} {render} 
		on:search={e => dispatch('search', { type: 'hash', value: e.detail })}	
		search={query} hasSearch />
</div>