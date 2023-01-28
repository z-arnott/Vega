import { expect, jest, test } from '@jest/globals';
import { supabase } from '@utils/supabase';
import {
  Package,
  Vulnerability,
  PackageViewParam,
  VulnerabilityViewParam,
  severityRating
} from '@utils/types.utils';
import {
  writePackage,
  readPackage,
  readAllPackages,
  writeVuln,
  readVulnsBySession,
  readVulnsByPkg,
  readVulnerabilitiesDashboard,
  readPackagesDashboard
} from '@utils/storageFacade.utils';

//Set up test data
jest.setTimeout(20000);
let sessionId = 9927;
let packages: Package[] = [
  {
    consRisk: 0,
    cpeName: 'cpe:2.3:a:pivotal_software:spring_framework:4.1.0:*:*:*:*:*:*:*',
    highestRisk: 0,
    ref: 'SPDXRef-Package',
    impact: null,
    likelihood: null,
    name: 'glibc',
    purl: null,
    version: '2.11.1',
  },
  {
    consRisk: 0,
    cpeName: null,
    highestRisk: 0,
    ref: 'SPDXRef-fromDoap-1',
    impact: null,
    likelihood: null,
    name: 'Apache Commons Lang',
    purl: null,
    version: null,
  },
  {
    consRisk: 0,
    cpeName: null,
    highestRisk: 0,
    ref: 'SPDXRef-fromDoap-0',
    impact: null,
    likelihood: null,
    name: 'Jena',
    purl: null,
    version: null,
  },
  {
    consRisk: 0,
    cpeName: null,
    highestRisk: 0,
    ref: 'SPDXRef-Saxon',
    impact: null,
    likelihood: null,
    name: 'Saxon',
    purl: null,
    version: '8.8',
  },
  {
    consRisk: 0,
    cpeName: 'cpe:2.3:a:pivotal_software:4.1.0:*:*:*:*:*:*:*',
    highestRisk: 0,
    ref: 'SPDXRef-Test',
    impact: null,
    likelihood: null,
    name: 'gTestc',
    purl: null,
    version: '2.11.1',
  },
];

let vulnerabilities: Vulnerability[] = [
  {
    cveId: 'CVE-2022-1471',
    cvss2: 'AV:N/AC:L/Au:S/C:N/I:P/A:N',
    impact: 0,
    likelihood: 0,
    packageRef: 'SPDXRef-Package',
    risk: 0,
  },
  {
    cveId: 'CVE-2022-25857',
    cvss2: 'AV:N/AC:L/Au:S/C:P/I:P/A:P',
    impact: 0,
    likelihood: 0,
    packageRef: 'SPDXRef-Package',
    risk: 0,
  },
  {
    cveId: 'CVE-2022-38749',
    cvss2: 'AV:N/AC:M/Au:N/C:N/I:P/A:N',
    impact: 0,
    likelihood: 0,
    packageRef: 'SPDXRef-fromDoap-1',
    risk: 0,
  },
  {
    cveId: 'CVE-2022-38751',
    cvss2: 'AV:N/AC:L/Au:S/C:N/I:P/A:N',
    impact: 0,
    likelihood: 0,
    packageRef: 'SPDXRef-fromDoap-0',
    risk: 0,
  },
  {
    cveId: 'CVE-2022-38752',
    cvss2: 'AV:N/AC:M/Au:S/C:C/I:P/A:N',
    impact: 0,
    likelihood: 0,
    packageRef: 'SPDXRef-fromDoap-0',
    risk: 0,
  },
  {
    cveId: 'CVE-2022-41854',
    cvss2: 'AV:N/AC:M/Au:N/C:N/I:P/A:N',
    impact: 0,
    likelihood: 0,
    packageRef: 'SPDXRef-Package',
    risk: 0,
  },
  {
    cveId: 'CVE-2022-38750',
    cvss2: 'AV:N/AC:H/Au:N/C:P/I:P/A:C',
    impact: 0,
    likelihood: 0,
    packageRef: 'SPDXRef-fromDoap-0',
    risk: 0,
  },
];

async function clear_test_packages() {
  for (let pkg of packages) {
    const { error } = await supabase
      .from('packages')
      .delete()
      .eq('package_ref', pkg.ref)
      .eq('sessionid', sessionId);
  }
 
}

async function clear_test_vulnerabilites() {
  for (let v of vulnerabilities) {
    const { error } = await supabase
      .from('vulnerabilities')
      .delete()
      .eq('cveidstring', v.cveId);
  }
}

async function clear_test_junction() {
  const { data } = await supabase
    .from('packages')
    .select('packageid')
    .eq('sessionid', sessionId);
  if (data) {
    let arr = Object.values(data);
    const { error } = await supabase
      .from('junction')
      .delete()
      .in('packageid', arr);
  }
  return data;
}

async function cleanup() {
  return {
    result1: await clear_test_junction(),
    result2: await clear_test_packages(),
    result3: await clear_test_vulnerabilites(),
  };
}

async function setup() {
  return cleanup().then(async () => {
    for (let pkg of packages) {
      await writePackage(pkg, sessionId);
    }
    for (let v of vulnerabilities) {
      await writeVuln(v, sessionId);
    }
  });
}

beforeAll(async () => {
  return setup();
});

//Test 1: Can Write and read one package
test('Test 1: Write and read one package', async () => {
  return readPackage(packages[0].ref, sessionId).then((pkg) => {
    expect(pkg).toStrictEqual(packages[0]);
  });
});

//Test 2: Can read all packages from a session
test('Test 2: Read all packages from a session', async () => {
  return readAllPackages(sessionId).then((pkgs) => {
    expect(pkgs.length).toEqual(packages.length);
    expect(pkgs).toContainEqual(packages[0]);
    expect(pkgs).toContainEqual(packages[1]);
    expect(pkgs).toContainEqual(packages[2]);
    expect(pkgs).toContainEqual(packages[3]);
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
test('Test 3: Update existing package (does NOT duplicate)', async () => {
  await writePackage(updatedPkg, sessionId);
  return readAllPackages(sessionId).then((pkgs) => {
    expect(pkgs).toContainEqual(updatedPkg);
    expect(pkgs).not.toContainEqual(packages[0]);
  });
});

//Test 4: Try to read package that does not exist in DB
test('Test 4: Read package that does not exist in DB', async () => {
  return readPackage('unknown', sessionId).then((pkgs) => {
    expect(pkgs).toEqual(null);
  });
});

//Test 5: Try to read all packages for sessionId that does not exist in DB
test('Test 5: Read packages by sessionId not in DB', async () => {
  return readAllPackages(1027).then((pkgs) => {
    expect(pkgs).toEqual([]);
  });
});

//Test 7: Can read one cve
test('Test 7: Read one cve', async () => {
  return readVulnsByPkg(vulnerabilities[0].packageRef, sessionId).then(
    (cves) => {
      expect(cves).toContainEqual(vulnerabilities[0]);
    }
  );
});

//Test 8: Can read multiple cves by package
test('Test 8: Can read all vulnerabilities for a package', async () => {
  for (let v of vulnerabilities) {
    await writeVuln(v, sessionId);
  }
  return readVulnsByPkg(vulnerabilities[0].packageRef, sessionId).then(
    (cves) => {
      expect(cves.length).toEqual(3);
    }
  );
});

//Test 9: Can read multiple cves by session
test('Test 8: Can read all vulnerabilities for a session', async () => {
  return readVulnsBySession(sessionId).then((cves) => {
    expect(cves.length).toEqual(vulnerabilities.length);
  });
});

let updatedCve = {
  cveId: 'CVE-2022-25857',
  cvss2: 'AV:N/AC:L/Au:S/C:P/I:P/A:P',
  impact: 25,
  likelihood: 0.66,
  packageRef: 'SPDXRef-Package',
  risk: 89,
};
//Test 9: Update existing package (does NOT duplicate)
test('Test 9: Updated existing cve (no duplicates)', async () => {
  return writeVuln(updatedCve, sessionId).then(async () => {
    return readVulnsBySession(sessionId).then((cves) => {
      expect(cves).toContainEqual(updatedCve);
      expect(cves).not.toContainEqual(vulnerabilities[1]);
    });
  });
});

//Test 10: Read vulnerabilities not present in database
test('Test 10: Read vulnerabilities not present in database', async () => {
  return readVulnsBySession(1027).then((cves) => {
    expect(cves).toEqual([]);
  });
});

//Test 11: Read vulnerabilities not present in database
test('Test 11: Read vulnerabilities not present in database', async () => {
  return readVulnsByPkg('unknown', sessionId).then((cves) => {
    expect(cves).toEqual([]);
  });
});


//Test 12: Vulnerabilities dashboard
test('Test 12: Sorted Dashboard Data (cves)', async () => {
  return readVulnerabilitiesDashboard(
    sessionId,
    VulnerabilityViewParam.IMPACT,
    VulnerabilityViewParam.RISK,
    severityRating.LOW,
    severityRating.CRITICAL,
    1
  ).then((cves) => {
    console.log('Test 12 output:\n', JSON.stringify(cves, null, 2));
  });
});

//Test 13: Dashboard fn
test('Test 13: Sorted Dashboard Data (packages)', async () => {
  return readPackagesDashboard(
    sessionId,
    PackageViewParam.COMPONENT_REF,
    PackageViewParam.HIGHEST_RISK,
    severityRating.LOW,
    severityRating.CRITICAL,
    1
  ).then((cves) => {
    console.log('Test 13 output:\n', JSON.stringify(cves, null, 2));
  });
});
