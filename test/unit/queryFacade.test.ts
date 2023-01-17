import { Query, VulDatabase, Vulnerability } from '@utils/types.utils';
import { sendQuery } from '@utils/queryFacade.utils';
import dotenv from 'dotenv';

//Setup
dotenv.config();
const API_KEY = process.env.API_KEY as string;
const AUTH = process.env.AUTHORIZATION as string;
jest.setTimeout(20000);

//Test 1: NVD valid CVEID
let query1: Query = {
  database: VulDatabase.NVD,
  method: 'get',
  headers: { authKey: 'apiKey', authValue: API_KEY },
  params: { searchKey: 'cveId', searchValue: 'CVE-2021-20089' },
  body: null,
};

let expectedResult1: Vulnerability[] = [
  {
    cveId: 'CVE-2021-20089',
    cvss2: 'AV:N/AC:L/Au:S/C:P/I:P/A:P',
    packageRef: '-1',
    impact: -1,
    likelihood: -1,
    risk: -1,
  },
];

test('Test 1: NVD with valid cveId', () => {
  return sendQuery(query1).then((data) => {
    expect(data.sort()).toStrictEqual(expectedResult1.sort());
  });
});

//Test 2: NVD query by valid cpename
let query2: Query = {
  database: VulDatabase.NVD,
  method: 'get',
  headers: { authKey: 'apiKey', authValue: API_KEY },
  params: {
    searchKey: 'cpeName',
    searchValue: 'cpe:2.3:a:1e:client:4.1.0.267:*:*:*:*:windows:*:*',
  },
  body: null,
};

let expectedResult2: Vulnerability[] = [
  {
    cveId: 'CVE-2020-16268',
    cvss2: 'AV:N/AC:L/Au:S/C:P/I:P/A:P',
    packageRef: '-1',
    impact: -1,
    likelihood: -1,
    risk: -1,
  },
  {
    cveId: 'CVE-2020-27643',
    cvss2: 'AV:N/AC:L/Au:S/C:N/I:P/A:N',
    packageRef: '-1',
    impact: -1,
    likelihood: -1,
    risk: -1,
  },
];

test('Test 2: NVD Valid cpeName', () => {
  return sendQuery(query2).then((data) => {
    expect(data.sort()).toStrictEqual(expectedResult2.sort());
  });
});

//Test 3: NVD query by valid keyword
let query3: Query = {
  database: VulDatabase.NVD,
  method: 'get',
  headers: { authKey: 'apiKey', authValue: API_KEY },
  params: { searchKey: 'keywordSearch', searchValue: 'Bootstrap v3.4.1' },
  body: null,
};

let expectedResult3: Vulnerability[] = [
  {
    cveId: 'CVE-2019-8331',
    cvss2: 'AV:N/AC:M/Au:N/C:N/I:P/A:N',
    packageRef: '-1',
    impact: -1,
    likelihood: -1,
    risk: -1,
  },
];

test('Test 3: NVD valid keyword', () => {
  return sendQuery(query3).then((data) => {
    expect(data).toStrictEqual(expectedResult3);
  });
});

//Test 4 query by keyword not in nvd
let query4: Query = {
  database: VulDatabase.NVD,
  method: 'get',
  headers: { authKey: 'apiKey', authValue: API_KEY },
  params: { searchKey: 'keywordSearch', searchValue: 'Bootstrapv3.4.1' },
  body: null,
};

let expectedResult4: any = [];

test('Test 4: NVD valid keyword w/o matches', () => {
  return sendQuery(query4).then((data) => {
    expect(data.sort()).toStrictEqual(expectedResult4.sort());
  });
});

//Test 5 bad api key
let query5: Query = {
  database: VulDatabase.NVD,
  method: 'get',
  headers: { authKey: 'apiKey', authValue: 'badKey' },
  params: { searchKey: 'cveId', searchValue: 'CVE-2021-20089' },
  body: null,
};

let expectedResult5: any = [];

test('Test 5: NVD bad api key', () => {
  return sendQuery(query5).then((data) => {
    expect(data.sort()).toStrictEqual(expectedResult5.sort());
  });
});

//Test6: SONATYPE query by valid purl
let query6: Query = {
  database: VulDatabase.SONATYPE,
  method: 'post',
  headers: {
    authKey: 'Authorization',
    authValue: 'Basic ' + AUTH,
  },
  params: { searchKey: '', searchValue: null },
  body: {
    coordinates: ['pkg:maven/org.yaml/snakeyaml@1.30'],
  },
};

let expectedResult6: Vulnerability[] = [
  {
    cveId: 'CVE-2022-1471',
    cvss2: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    impact: -1,
    likelihood: -1,
    packageRef: '-1',
    risk: -1,
  },
  {
    cveId: 'CVE-2022-25857',
    cvss2: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    impact: -1,
    likelihood: -1,
    packageRef: '-1',
    risk: -1,
  },
  {
    cveId: 'CVE-2022-38749',
    cvss2: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H',
    impact: -1,
    likelihood: -1,
    packageRef: '-1',
    risk: -1,
  },
  {
    cveId: 'CVE-2022-38751',
    cvss2: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H',
    impact: -1,
    likelihood: -1,
    packageRef: '-1',
    risk: -1,
  },
  {
    cveId: 'CVE-2022-38752',
    cvss2: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H',
    impact: -1,
    likelihood: -1,
    packageRef: '-1',
    risk: -1,
  },
  {
    cveId: 'CVE-2022-41854',
    cvss2: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H',
    impact: -1,
    likelihood: -1,
    packageRef: '-1',
    risk: -1,
  },
  {
    cveId: 'CVE-2022-38750',
    cvss2: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H',
    impact: -1,
    likelihood: -1,
    packageRef: '-1',
    risk: -1,
  },
];

test('Test 6: SONATYPE valid purl', () => {
  return sendQuery(query6).then((data) => {
    expect(data.sort()).toStrictEqual(expectedResult6.sort());
  });
});

//Test7: SONATYPE query by valid purl - not in SONATYPE
let query7: Query = {
  database: VulDatabase.SONATYPE,
  method: 'post',
  headers: {
    authKey: 'Authorization',
    authValue: 'Basic ' + AUTH,
  },
  params: { searchKey: '', searchValue: null },
  body: {
    coordinates: ['pkg:maven/org.yaml/snakeyaml@1.77'],
  },
};

let expectedResult7: any = [];

test('Test 7: SONATYPE valid purl not in db', () => {
  return sendQuery(query7).then((data) => {
    expect(data.sort()).toStrictEqual(expectedResult7.sort());
  });
});

//Test8: SONATYPE bad auth
let query8: Query = {
  database: VulDatabase.SONATYPE,
  method: 'post',
  headers: { authKey: 'Authorization', authValue: 'Basic ' + 'badAuth' },
  params: { searchKey: '', searchValue: null },
  body: {
    coordinates: ['pkg:maven/org.yaml/snakeyaml@1.77'],
  },
};

let expectedResult8: any = [];

test('Test 8: SONATYPE valid purl not in db', () => {
  return sendQuery(query8).then((data) => {
    expect(data.sort()).toStrictEqual(expectedResult8.sort());
  });
});

//Test9: SONATYPE with invalid body
let query9: Query = {
  database: VulDatabase.SONATYPE,
  method: 'post',
  headers: { authKey: 'Authorization', authValue: 'Basic ' + 'badAuth' },
  params: { searchKey: '', searchValue: null },
  body: 'badBody',
};

let expectedResult9: any = [];

test('Test 9: SONATYPE invalid body', () => {
  return sendQuery(query9).then((data) => {
    expect(data.sort()).toStrictEqual(expectedResult9.sort());
  });
});
