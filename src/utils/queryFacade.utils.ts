import {Query} from '@utils/types.utils';
import {Vulnerability} from '@utils/types.utils';
import {VulDatabase} from '@utils/types.utils';
import axios from 'axios'

/**HTTP GET */
export async function getVulnerabilities(query: Query){
	let config: any = {
		method: query.method,
		url: query.url,
		headers: {
			[query.headers.authKey]: query.headers.authValue,
		},
		params:{
			[query.params.searchKey]: query.params.searchValue
		},
		data: query.body
	}
	return axios(
		config
	).then((response)=> {
		return response.data;
	});
}

/**Response Cleaner Interface */
interface QueryCleaner {
	(rawResponse: any): Vulnerability[];
 };

//Cleaner instances
let nvdCleaner: QueryCleaner;
let sonatypeCleaner: QueryCleaner;

//Cleaner implementaions
nvdCleaner = function(rawResponse): Vulnerability[] {
	let vulns: Vulnerability[] = [];
	let rawVulns: any = rawResponse.vulnerabilities;	//get all vulnerabilities
	
	//Create Vulnerability for each cve in response
	rawVulns.forEach(function(cve : any) { 
		let v: Vulnerability = {
			cveId: cve['cve'].id,
			packgaeId: -1,
			impact: -1,
			likelihood: -1,
			risk: -1,
			cvss2: ""
		}
		//Get correct CVSS version
		if(cve['cve']['metrics'].hasOwnProperty("cvssMetricV2")){//V2
			v.cvss2 = cve['cve']['metrics']['cvssMetricV2'][0]['cvssData']['vectorString'];
		}
		else if(cve['cve']['metrics'].hasOwnProperty("cvssMetricV31")){//V3
			//map cvss2 to cvss3
		}
		vulns.push(v);
	})
	return vulns;
}

sonatypeCleaner = function(rawResponse): Vulnerability[] {
	let vulns: Vulnerability[] = [];
	let rawVulns: any = rawResponse[0].vulnerabilities;	//get all vulnerabilities
	console.log(rawVulns);

	//Create Vulnerability for each cve in response
	rawVulns.forEach(function(cve : any) { 
		let v: Vulnerability = {
			cveId: cve.id,
			packgaeId: -1,
			impact: -1,
			likelihood: -1,
			risk: -1,
			cvss2: ""
		}
		
		//Get correct CVSS version
		if(cve.hasOwnProperty("cvssVector")){
			let cvssVector: string = cve.cvssVector;
			
			if(cvssVector.startsWith('CVSS:2')){//V2
				v.cveId = cvssVector;
			}
			else if(cvssVector.startsWith('CVSS:3')){//V3
				//TO-DO:map cvss2 to cvss3
				v.cveId = cvssVector;
			}
		}
		vulns.push(v);
	})

	console.log(vulns); 
	return vulns;
	
}


/** Query Facade Functions */
//Sends one query, returns list of Vulnerabilities
export function sendQuery(query: Query) : Vulnerability[] {
	let resp = getVulnerabilities(query);
	switch(query.database){
		case VulDatabase.NVD: {
			return nvdCleaner(resp);
		}
		default: {
			console.log("Query Facade: database not supported!");
			return [];
		} 
	}
}

/** Module Exports */
export {nvdCleaner, sonatypeCleaner}