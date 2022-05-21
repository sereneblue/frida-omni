<script lang="ts">
	import type { HashData } from "../types.ts";
	import OmniTable from "./OmniTable.svelte";

	export let data = [];

	const headers = ["Timestamp", "URL"];
	const render = [
		{
			fn: (data) => data.timestamp,
			clipboard: false,
		},
		{
			fn: (data) => data.url,
			clipboard: true,
		}
	]
</script>

<div>
	<OmniTable {headers} {data} {render} />
</div>