import type { ResponseData } from "./types";

class Omni {
	static base_url: string = "http://" + window.location.host;
	base_url: string = "http://" + window.location.host;
	logs: object;

	constructor() {
		this.logs = {
			pkg_info: true,
			crypto: true,
			fs: true,
			hash: true,
			http: true,
			shared_prefs: true,
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

	async getLogData(deviceId: string, appId: string, queryData: object): Promise<ResponseData> {
		let enabledLogs = { logs : Object.keys(this.logs).filter(k => this.logs[k]), deviceId, appId, queryData }

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

	async postAction(deviceId: string, appId: string, action: string): Promise<ResponseData> {
		const formData = new URLSearchParams();
		formData.append('deviceId', deviceId);
		formData.append('appId', appId);
		formData.append('action', action);

		let res = await fetch(this.base_url + '/api/action', {
		    method: 'POST',
		    headers: {
		      'Content-Type': 'application/x-www-form-urlencoded',
		    },
		    body: formData
		  });

		let data = await res.json();

		return data;
	}

	saveFile(content: string, appId: string) {
	    const downloadLink = document.createElement('a');
	    document.body.appendChild(downloadLink);

	    downloadLink.href = `data:application/x-sqlite3;base64,${content}`;
	    downloadLink.target = '_self';
	    downloadLink.download = `omni_${appId}_${new Date().getTime()}.db`;
	    downloadLink.click();
	}
}

export default Omni;