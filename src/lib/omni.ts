import type { ResponseData } from "./types";

class Omni {
	static base_url: string = "http://localhost:8080";
	base_url: string = "http://localhost:8080";

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
}

export default Omni;