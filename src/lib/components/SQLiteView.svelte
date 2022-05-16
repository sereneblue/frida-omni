<script lang="ts">
	import type { HashData } from "../types.ts";
	import OmniTable from "./OmniTable.svelte";

	export let data = [];

	const headers = ["DB", "Method", "Value"];
	const render = [
		{
			fn: (data) => data.db,
			clipboard: false,
		},
		{
			fn: (data) => data.method,
			clipboard: false,
		},
		{
			fn: (data) => data.value,
			clipboard: true,
		}
	]
</script>

<div>
	<OmniTable {headers} {data} {render} />
</div>