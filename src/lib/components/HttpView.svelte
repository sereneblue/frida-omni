<script lang="ts">
	import OmniTable from "./OmniTable.svelte";
	import { createEventDispatcher } from 'svelte';
	import { formatDistance } from 'date-fns';

	const dispatch = createEventDispatcher();

	export let data = [];
	export let query = "";

	const headers = ["Time", "URL"];
	const render = [
		{
			fn: (data) => formatDistance(new Date(data.timestamp), new Date(), { addSuffix: true }),
			clipboard: false,
		},
		{
			fn: (data) => data.url,
			clipboard: true,
		}
	]
</script>

<div>
	<OmniTable {headers} {data} {render} 
		on:search={e => dispatch('search', { type: 'http', value: e.detail })}	
		search={query} hasSearch />
</div>