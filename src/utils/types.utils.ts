export enum VulDatabase{
    NVD = 1,
    Sonatype,
    /*Add supported DBs here */
}

export interface Query {
    database: VulDatabase,
    method: string,
    url: string,
    headers: {authKey: string, authValue: string},
    params: {searchKey: string, searchValue: string| null},
    body: any | null
}

export interface Package {
    id: number,
    name: string,
    purl: string,
    cpeName: string,
    impact: number,
    likelihood: number,
    consRisk: number,
    highestRisk: number,
}

export interface Vulnerability {
    cveId: string,
    packgaeId: number,
    cvss2: string,
    impact: number,
    likelihood: number,
    risk: number,
}