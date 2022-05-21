<script lang="ts">
	import OmniTable from "./OmniTable.svelte";

	export let data = [];

	const headers = ["Timestamp", "Path"];
	const render = [
		{
			fn: (data) => data.timestamp,
			clipboard: false,
		},
		{
			fn: (data) => data.path,
			clipboard: true,
			fullwidth: true
		}
	]
</script>

<div>
	<OmniTable {headers} {data} {render} />
</div>