import { expect, jest, test } from '@jest/globals';
import dotenv from 'dotenv';
import { supabase } from '@utils/supabase';
import {Package} from '@utils/types.utils';
import {writePackage, readPackage, readAllPackages} from '@utils/storageFacade.utils'
//Setup
dotenv.config();
const supabaseUrl = process.env.SUPABASE_URL as string;
const supabaseKey = process.env.SUPABASE_KEY as string;

//Set up test data
let sessionId = 9927;
let packages: Package[] = [
  {
    consRisk: null,
    cpeName: 'cpe:2.3:a:pivotal_software:spring_framework:4.1.0:*:*:*:*:*:*:*',
    highestRisk: null,
    ref: 'SPDXRef-Package',
    impact: null,
    likelihood: null,
    name: 'glibc',
    purl: null,
    version: '2.11.1',
  },
  {
    consRisk: null,
    cpeName: null,
    highestRisk: null,
    ref: 'SPDXRef-fromDoap-1',
    impact: null,
    likelihood: null,
    name: 'Apache Commons Lang',
    purl: null,
    version: null,
  },
  {
    consRisk: null,
    cpeName: null,
    highestRisk: null,
    ref: 'SPDXRef-fromDoap-0',
    impact: null,
    likelihood: null,
    name: 'Jena',
    purl: null,
    version: null,
  },
  {
    consRisk: null,
    cpeName: null,
    highestRisk: null,
    ref: 'SPDXRef-Saxon',
    impact: null,
    likelihood: null,
    name: 'Saxon',
    purl: null,
    version: '8.8',
  },
];

let vulnerabilities: Vulnerability[] = [
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

async function clear_test_data(){
  for(let pkg of packages){
    const { error } = await supabase
      .from('packages')
      .delete()
      .eq('package_ref', pkg.ref)
      .eq('sessionid', sessionId );
}}

clear_test_data();

//Test 1: Can Write and read one package
test('Test 1: Write and read one package', async() => {
  await writePackage(packages[0], sessionId);
  return readPackage(packages[0].ref, sessionId)
    .then((pkg) => {
      expect(pkg).toStrictEqual(packages[0]);
  });
});

//Test 2: Can read all packages from a session
test('Test 2: Read all packages from a session', async() => {
  for(let pkg of packages){
    await writePackage(pkg, sessionId);
  }
  return readAllPackages(sessionId)
    .then((pkgs) => {
      expect(pkgs).toStrictEqual(packages);
  });
});

let updatedPkg = {
  consRisk: 55,
  cpeName: 'cpe:2.3:a:pivotal_software:spring_framework:4.1.0:*:*:*:*:*:*:*',
  highestRisk: null,
  ref: 'SPDXRef-Package',
  impact: 39,
  likelihood: 0.8,
  name: 'glibc',
  purl: null,
  version: '2.11.1',
};

//Test 3: Update existing package (does NOT duplicate)
test('Test 3: Read all packages from a session', async() => {
  await writePackage(updatedPkg, sessionId);
  return readAllPackages(sessionId)
    .then((pkgs) => {
      expect(pkgs).toContainEqual(updatedPkg);
      expect(pkgs).not.toContainEqual(packages[0]);
  });
});

//Test 4: Can Write and read one Vulnerability
test('Test 3: Read all packages from a session', async() => {
  await writePackage(updatedPkg, sessionId);
  return readAllPackages(sessionId)
    .then((pkgs) => {
      expect(pkgs).toContainEqual(updatedPkg);
      expect(pkgs).not.toContainEqual(packages[0]);
  });
});