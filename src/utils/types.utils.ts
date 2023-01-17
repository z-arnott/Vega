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
  ref: string;
  name: string;
  purl: string | null;
  cpeName: string | null;
  impact: number | null;
  likelihood: number | null;
  consRisk: number | null;
  highestRisk: number | null;
  version: string | null;
}

/**
 * Represents a cve vulnerability
 */
export interface Vulnerability {
  cveId: string;
  packageRef: string;
  cvss2: string;
  impact: number;
  likelihood: number;
  risk: number;
}