<script lang="ts">
	export let count = 0;

	const readableNumber = (num: number): string => {
	    var s = ['', 'K', 'M', 'B'];
	    var e = Math.floor(Math.log(num) / Math.log(1000));

	    return (((num / Math.pow(1000, e)).toPrecision(3)) / 1) + s[e];
	}
</script>

{#if count > 0}
	<span class="rounded-full bg-teal-600 text-xs text-white font-bold opacity-100 px-1.5 py-0.5">
		{readableNumber(count)}
	</span>
{/if}
