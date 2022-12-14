import { Query, VulDatabase } from '@utils/types.utils';
import { Vulnerability } from '@utils/types.utils';
import axios from 'axios';

/***************** GET VULNERABILITIES FROM EXT DATABASES ****************************/
export async function getVulnerabilities(query: Query) {
  let config: any = {
    method: query.method,
    url: query.database,
    headers: {
      [query.headers.authKey]: query.headers.authValue,
    },
    params: {
      [query.params.searchKey]: query.params.searchValue,
    },
    data: query.body,
  };

  return axios(config)
    .then((response) => {
      return response.data;
    })
    .catch(function (error) {
      if (error.response) {
        // The request was made and the server responded with a status code
        // that falls out of the range of 2xx
        console.log(error.response.data);
        console.log(error.response.status);
        console.log(error.response.headers);
      } else if (error.request) {
        // The request was made but no response was received
        // `error.request` is an instance of XMLHttpRequest in the browser and an instance of
        // http.ClientRequest in node.js
        console.log(error.request);
      } else {
        // Something happened in setting up the request that triggered an Error
        console.log('Error', error.message);
      }
      console.log(error.config);
      return error.response.status;
    });
}

/****************** RESPONSE CLEANER INTERFACE **********************/
interface QueryCleaner {
  (rawResponse: any): Vulnerability[];
}

//Cleaner instances
let nvdCleaner: QueryCleaner;
let sonatypeCleaner: QueryCleaner;

//Cleaner implementaions
nvdCleaner = function (rawResponse): Vulnerability[] {
  let vulns: Vulnerability[] = [];
  let rawVulns: any = rawResponse.vulnerabilities; //get all vulnerabilities

  //Create Vulnerability for each cve in response
  rawVulns.forEach(function (cve: any) {
    let v: Vulnerability = {
      cveId: cve['cve'].id,
      packgaeId: -1,
      impact: -1,
      likelihood: -1,
      risk: -1,
      cvss2: '',
    };
    //Get correct CVSS version
    if (cve['cve']['metrics'].hasOwnProperty('cvssMetricV2')) {
      //V2
      v.cvss2 =
        cve['cve']['metrics']['cvssMetricV2'][0]['cvssData']['vectorString'];
    } else if (cve['cve']['metrics'].hasOwnProperty('cvssMetricV31')) {
      //V3
      //map cvss2 to cvss3
    }
    vulns.push(v);
  });
  return vulns;
};

sonatypeCleaner = function (rawResponse): Vulnerability[] {
  let vulns: Vulnerability[] = [];

  let rawVulns: any = rawResponse[0].vulnerabilities;

  //Create Vulnerability for each cve in response
  rawVulns.forEach(function (cve: any) {
    let v: Vulnerability = {
      cveId: cve.id,
      packgaeId: -1,
      impact: -1,
      likelihood: -1,
      risk: -1,
      cvss2: '',
    };

    //Get correct CVSS version
    if (cve.hasOwnProperty('cvssVector')) {
      let cvssVector: string = cve.cvssVector;

      if (cvssVector.startsWith('CVSS:2')) {
        //V2
        v.cvss2 = cvssVector;
      } else if (cvssVector.startsWith('CVSS:3')) {
        //V3
        //TO-DO:map cvss2 to cvss3
        v.cvss2 = cvssVector;
      }
    }
    vulns.push(v);
  });

  return vulns;
};

/* Register cleaning strategies here */
let cleaningStrategy = {
  [VulDatabase.SONATYPE]: sonatypeCleaner,
  [VulDatabase.NVD]: nvdCleaner,
};

/****************** QUERY FACADE API **********************/
//Sends one query, returns list of Vulnerabilities
async function sendQuery(query: Query) {
  return getVulnerabilities(query).then((response) => {
    //Handle error
    if (!isNaN(response)) {
      //To-do error handleide
      return [];
    }
    return cleaningStrategy[query.database](response);
  });
}

/** Module Exports */
export { sendQuery };
