<script lang="ts">
	import type { HashData } from "../types.ts";
	import OmniTable from "./OmniTable.svelte";

	export let data = {};

	const transformedData = (d: object): object => {
		let tmp = [];

		if (d.activities) {
			for (let i = 0; i < d.activities.length; i++) {
				tmp.push({
					id: `act-${i}`,
					type: 'Activity',
					name: d.activities[i].name,
					value: d.activities[i].value == 1 ? "Exported": "Not exported"
				});
			}

			for (let i = 0; i < d.permissions.length; i++) {
				tmp.push({
					id: `perms-${i}`,
					type: 'Permissions',
					name: d.permissions[i].name,
					value: d.permissions[i].value == 1 ? "Granted": "Not granted"
				});
			}

			for (let i = 0; i < d.providers.length; i++) {
				tmp.push({
					id: `prov-${i}`,
					type: 'Providers',
					name: d.providers[i].name,
					value: d.providers[i].value == 1 ? "Exported": "Not exported"
				});
			}

			for (let i = 0; i < d.receivers.length; i++) {
				tmp.push({
					id: `rcv-${i}`,
					type: 'Receivers',
					name: d.receivers[i].name,
					value: d.receivers[i].value == 1 ? "Exported": "Not exported"
				});
			}

			for (let i = 0; i < d.services.length; i++) {
				tmp.push({
					id: `srv-${i}`,
					type: 'Services',
					name: d.services[i].name,
					value: d.services[i].value == 1 ? "Exported": "Not exported"
				});
			}

			for (let i = 0; i < d.sharedLibs.length; i++) {
				tmp.push({
					id: `sl-${i}`,
					type: 'Shared Lib',
					name: d.sharedLibs[i].name,
					value: ""
				});
			}
		}

		return tmp;
	};

	const headers = ["Type", "Name", "Value"];
	const render = [
		{
			fn: (data) => data.type,
			clipboard: false,
		},
		{
			fn: (data) => data.name,
			clipboard: false,
			fullwidth: true
		},
		{
			fn: (data) => data.value,
			clipboard: false,
		},
	]
</script>

<div>
	<OmniTable {headers} data={transformedData(data)} {render} />
</div>