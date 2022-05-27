<script lang="ts">
	import OmniTable from "./OmniTable.svelte";

	export let data = [];

	const headers = ["Timestamp", "Method", "Value"];
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
			fn: (data) => data.value,
			clipboard: true,
			fullwidth: true
		}
	]
</script>

<div>
	<OmniTable {headers} {data} {render} />
</div>