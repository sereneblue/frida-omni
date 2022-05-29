<script lang="ts">
	import OmniTable from "./OmniTable.svelte";
	import { createEventDispatcher } from 'svelte';
	import { formatDistance } from 'date-fns';

	const dispatch = createEventDispatcher();

	export let data = [];
	export let filters = [];
	export let query = "";

	const headers = ["Time", "Hash", "Input", "Output"];
	const render = [
		{
			fn: (data) => formatDistance(new Date(data.timestamp), new Date(), { addSuffix: true }),
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
		on:filter={e => dispatch('filter', { type: 'hash', id: e.detail.id, checked: e.detail.checked })}
		on:search={e => dispatch('search', { type: 'hash', value: e.detail })}
		{filters} search={query} hasSearch />
</div>