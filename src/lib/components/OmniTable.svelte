<script lang="ts">
	import OmniSearch from "./OmniSearch.svelte";
	import OmniTableText from "./OmniTableText.svelte";

	export let data = [];
	export let headers = [];
	export let render = [];

	export let search;
	export let hasSearch = false;
</script>

<div>
	{#if hasSearch}
		<div class="flex gap-x-1 mb-2">
			{#if hasSearch}
				<OmniSearch {search} on:search />
			{/if}
		</div>
	{/if}
	<table class="w-full text-left text-gray-400">
	    <thead class="text-xs uppercase bg-gray-700 text-gray-400">
	    	<tr>
		    	{#each headers as header}
	                <th scope="col" class="px-4 py-2">
						{header}
					</th>
				{/each}
	    	</tr>
		</thead>
		<tbody>
			{#each data as row (row.id)}
		        <tr class="bg-white border-b bg-gray-800 border-gray-700" data-id={row.id} data-expanded={false}>
		       		{#each render as r}
	                    <td class="px-4 py-2">
	                    	<OmniTableText content={r.fn(row)} canCopy={r.clipboard} fullwidth={r.fullwidth} />
		                </td>
			        {/each}
		        </tr>
			{/each}
	   </tbody>
	</table>
</div>