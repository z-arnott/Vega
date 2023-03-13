import {
  analyzeSystem,
  analyzePackage,
  analyzeVulnerability,
} from '@services/riskAnalysis.services';
import { Package, Vulnerability } from '@utils/types.utils';

//Analyze CVEs
let inputCVEs: Vulnerability[] = [
  {
    cveId: 'CVE-2021-20089',
    packageRef: '1',
    cvss2: 'AV:N/AC:L/Au:N/C:C/I:C/A:C',
    impact: 0,
    likelihood: -1,
    risk: 0,
  },
  {
    cveId: 'CVE-2021-20090',
    packageRef: '1',
    cvss2: 'AV:N/AC:L/Au:S/C:N/I:P/A:C',
    impact: -1,
    likelihood: -1,
    risk: -1,
  },
  {
    cveId: 'CVE-2021-20091',
    packageRef: '1',
    cvss2: 'AV:L/AC:L/Au:N/C:P/I:P/A:P',
    impact: -1,
    likelihood: 0,
    risk: 0,
  },
];

let expectedCVEs: Vulnerability[] = [
  {
    cveId: 'CVE-2021-20089',
    packageRef: '1',
    cvss2: 'AV:N/AC:L/Au:N/C:C/I:C/A:C',
    impact: 100,
    likelihood: 1,
    risk: 100,
  },
  {
    cveId: 'CVE-2021-20090',
    packageRef: '1',
    cvss2: 'AV:N/AC:L/Au:S/C:N/I:P/A:C',
    impact: 50,
    likelihood: 0.6,
    risk: 30,
  },
  {
    cveId: 'CVE-2021-20091',
    packageRef: '1',
    cvss2: 'AV:L/AC:L/Au:N/C:P/I:P/A:P',
    impact: 50,
    likelihood: 0.4,
    risk: 20,
  },
];
analyzeVulnerability(inputCVEs[0]);
analyzeVulnerability(inputCVEs[1]);
analyzeVulnerability(inputCVEs[2]);
test('Test 1: analyze vulnerabilites', () => {
  expect(inputCVEs[0]).toEqual(expectedCVEs[0]);
  expect(inputCVEs[1]).toEqual(expectedCVEs[1]);
  expect(inputCVEs[2]).toEqual(expectedCVEs[2]);
});
//Test 2: Analyze Package
let inputPackage: Package = {
  name: 'polyfill-intl-normalizer',
  ref: '1',
  purl: 'pkg:composer/symfony/polyfill-intl-normalizer@1.23.0',
  cpeName: null,
  consRisk: null,
  highestRisk: null,
  version: '1.23.0',
};

let expectedPackage: Package = {
  name: 'polyfill-intl-normalizer',
  ref: '1',
  purl: 'pkg:composer/symfony/polyfill-intl-normalizer@1.23.0',
  cpeName: null,
  consRisk: 76,
  highestRisk: 100,
  version: '1.23.0',
};
analyzePackage(inputPackage, expectedCVEs);
test('Test 2: analyze packages', () => {
  expect(inputPackage).toEqual(expectedPackage);
});

//Test 3: Analyze System
let packages: Package[] = [
  {
    name: 'polyfill-intl-normalizer',
    ref: '1',
    purl: 'pkg:composer/symfony/polyfill-intl-normalizer@1.23.0',
    cpeName: null,
    consRisk: 76,
    highestRisk: 89,
    version: '1.23.0',
  },
  {
    name: 'polyfill-intl-normalizer',
    ref: '1',
    purl: 'pkg:composer/symfony/polyfill-intl-normalizer@1.23.0',
    cpeName: null,
    consRisk: 76,
    highestRisk: 0.2,
    version: '1.23.0',
  },
  {
    name: 'polyfill-intl-normalizer',
    ref: '1',
    purl: 'pkg:composer/symfony/polyfill-intl-normalizer@1.23.0',
    cpeName: null,
    consRisk: 76,
    highestRisk: 58,
    version: '1.23.0',
  },
];
