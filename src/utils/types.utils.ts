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
