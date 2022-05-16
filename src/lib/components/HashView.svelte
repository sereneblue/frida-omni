<script lang="ts">
	import OmniTable from "./OmniTable.svelte";

	export let data = [];

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
	<OmniTable {headers} {data} {render} />
</div>