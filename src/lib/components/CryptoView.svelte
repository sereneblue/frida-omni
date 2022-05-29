<script lang="ts">
	import OmniTable from "./OmniTable.svelte";
	import { createEventDispatcher } from 'svelte';
	import { formatDistance } from 'date-fns';

	const dispatch = createEventDispatcher();

	export let data = [];
	export let filters = [];
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
		on:filter={e => dispatch('filter', { type: 'crypto', id: e.detail.id, checked: e.detail.checked })}
		on:search={e => dispatch('search', { type: 'crypto', value: e.detail })}
		{filters} search={query} hasSearch />
</div>