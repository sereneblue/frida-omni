<script lang="ts">
	import OmniTable from "./OmniTable.svelte";

	export let data = [];

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
	<OmniTable {headers} {data} {render} />
</div>