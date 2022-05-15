<script lang="ts">
	import OmniTableText from "./OmniTableText.svelte";

	export let headers = [];
	export let data = [];
	export let render = [];
</script>

<table class="w-full text-left text-gray-500 dark:text-gray-400">
    <thead class="text-xs text-gray-700 uppercase bg-gray-50 dark:bg-gray-700 dark:text-gray-400">
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
	        <tr class="bg-white border-b dark:bg-gray-800 dark:border-gray-700" data-id={row.id} data-expanded={false}>
	       		{#each render as r}
                    <td class="px-4 py-2">
                    	<OmniTableText content={r.fn(row)} canCopy={r.clipboard} fullwidth={r.fullwidth} />
	                </td>
		        {/each}
	        </tr>
		{/each}
   </tbody>
</table>