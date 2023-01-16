/**
 * @enum Represents URLs of supported vulnerability databases
 */
export enum VulDatabase {
  NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0',
  SONATYPE = 'https://ossindex.SONATYPE.org/api/v3/authorized/component-report',
  /*Add supported DBs here */
}

/**
 * @enum Supported SBOM formats
 */
export enum SbomFormat {
  SPDX_JSON,
  SPDX_TAGVALUE,
  CYCLONEDX_XML,
  CYCLONEDX_JSON,
  /*Add supported sbom formats here */
}

/**
 * Generic query type used to config vulnerability search to external databases
 */
export interface Query {
  database: VulDatabase;
  method: string;
  headers: { authKey: string; authValue: string };
  params: { searchKey: string; searchValue: string | null };
  body: any | null;
}

/**
 * Represents a software package
 */
export interface Package {
  id: string;
  name: string;
  purl: string | undefined;
  cpeName: string | undefined;
  impact: number | undefined;
  likelihood: number | undefined;
  consRisk: number | undefined;
  highestRisk: number | undefined;
  version: string | undefined;
}

/**
 * Represents a cve vulnerability
 */
export interface Vulnerability {
  cveId: string;
  packgaeId: number;
  cvss2: string;
  impact: number;
  likelihood: number;
  risk: number;
}

//Task 6: Remove sessionid as a parameter here but can keep querying database with it
export interface DBPackage {
  packageid: number; //update from Package interface
  sessionid: number; //update from Package
  name: string | null
  packageversion?: string | null; //addition from Package interface
  consrisk: number | null; 
  impact: number | null;
  likelihood: number | null;
  highestrisk: number | null;
  purl: string | null;
  cpename: string | null;
}

export interface DBVulnerabilitybypid {
  packageid: number;
  vulnerabilities:{
    cveid: number; //update from Vulnerability interface
    //cvss2: string; 
    impact: number| null;
    likelihood: number| null;
    risk: number| null;
    description: string| null;
  }
}

export interface DBVulnerabilitybysid {
      junction: DBVulnerabilitybypid[]
}
  
export interface DBVulnerabilityInput {
    cveid: number; //update from Vulnerability interface
    //cvss2: string; 
    impact: number| null;
    likelihood: number| null;
    risk: number| null;
    description: string| null;
  }

export interface DBResponse{
  count: number | null;
  data: any;  
  error: string | null;
  status: number | null;
  statusText: string | null;     
}

// let expectedResult3: DBResponse ={
//   count: null,
//   data: expectedData3,
//   error: null,
//   status: 200,
//   statusText: "OK"
// } 
