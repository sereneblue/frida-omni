import type { ResponseData } from "./types";

class Omni {
	static base_url: string = "http://localhost:8080";
	base_url: string = "http://localhost:8080";
	logs: object;

	constructor() {
		this.logs = {
			pkg_info: true,
			hash: true,
			sqlite: true
		}
	}

	static async getApps(deviceId: string): Promise<ResponseData> {
		let res = await fetch(this.base_url + `/api/applications/${deviceId}`);
		let data = await res.json();

		return data;
	}

	static async getDevices(): Promise<ResponseData> {
		let res = await fetch(this.base_url + '/api/devices');
		let data = await res.json();

		return data;
	}

	async getLogData(): Promise<ResponseData> {
		let enabledLogs = { logs : Object.keys(this.logs).filter(k => this.logs[k]) }

		let res = await fetch(this.base_url + '/api/logs', {
		    method: 'POST',
		    headers: {
		      'Accept': 'application/json',
		      'Content-Type': 'application/json'
		    },
		    body: JSON.stringify(enabledLogs)
		  });

		let data = await res.json();

		return data;
	}
}

export default Omni;