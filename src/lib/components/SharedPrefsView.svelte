<script lang="ts">
	import OmniTable from "./OmniTable.svelte";
	import { formatDistance } from 'date-fns';

	export let data = [];

	const headers = ["Time", "Method", "Value"];
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
			fn: (data) => data.value,
			clipboard: true,
			fullwidth: true
		}
	]
</script>

<div>
	<OmniTable {headers} {data} {render} />
</div>