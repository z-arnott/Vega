export enum VulDatabase {
  NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0',
  SONATYPE = 'https://ossindex.SONATYPE.org/api/v3/authorized/component-report',
  /*Add supported DBs here */
}

export interface Query {
  database: VulDatabase;
  method: string;
  headers: { authKey: string; authValue: string };
  params: { searchKey: string; searchValue: string | null };
  body: any | null;
}

export interface Package {
  id: number;
  name: string;
  purl: string;
  cpeName: string;
  impact: number;
  likelihood: number;
  consRisk: number;
  highestRisk: number;
}

export interface Vulnerability {
  cveId: string;
  packgaeId: number;
  cvss2: string;
  impact: number;
  likelihood: number;
  risk: number;
}

export interface DBPackage {
  packageid: number;
  sessionid: number;
  name: string | null
  packageversion: string | null;
  consrisk: number | null; 
  impact: number | null;
  likelihood: number | null;
  highestrisk: number | null;
  purl: string | null;
  cpename: string | null;
}

export interface DBResponse{
  count: number | null;
  data: any;  
  error: string | null;
  status: number | null;
  statusText: string | null;     


}