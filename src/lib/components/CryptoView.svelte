<script lang="ts">
	import OmniSearch from "./OmniSearch.svelte";
	import OmniTable from "./OmniTable.svelte";
	import { createEventDispatcher } from 'svelte';
	import { formatDistance } from 'date-fns';

	const dispatch = createEventDispatcher();

	export let data = [];
	export let query = "";

	const headers = ["Time", "Method", "Params"];
	const render = [
		{
			fn: (data) => formatDistance(new Date(data.timestamp), new Date(), { addSuffix: true }),
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