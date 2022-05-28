<script lang="ts">
	import OmniSearch from "./OmniSearch.svelte";
	import OmniTable from "./OmniTable.svelte";
	import { createEventDispatcher } from 'svelte';

	const dispatch = createEventDispatcher();

	export let data = [];
	export let query = "";

	const headers = ["Timestamp", "Method", "Params"];
	const render = [
		{
			fn: (data) => data.timestamp,
			clipboard: false,
		},
		{
			fn: (data) => data.method,
			clipboard: false,
		},
		{
			fn: (data) => data.params,
			clipboard: true,
		}
	]
</script>

<div>
	<OmniTable {headers} {data} {render} 
		on:search={e => dispatch('search', { type: 'crypto', value: e.detail })}	
		search={query} hasSearch />
</div>