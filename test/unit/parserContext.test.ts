import { parse } from '@services/parserContext.services';
import fs from 'fs';
import path from 'path';
import { Package, SbomFormat } from '@utils/types.utils';

//Setup
function getAppRootDir(): string {
  let currentDir = __dirname;
  while (!fs.existsSync(path.join(currentDir, 'package.json'))) {
    currentDir = path.join(currentDir, '..');
  }
  return currentDir;
}
const sbom_filepath = 'test/sbom_examples/unit_tests';
const spdx_json = fs.readFileSync(
  path.join(getAppRootDir(), sbom_filepath, 'bom.spdx.json'),
  'utf-8'
);
const spdx = fs.readFileSync(
  path.join(getAppRootDir(), sbom_filepath, 'bom.spdx'),
  'utf-8'
);
const cyclonedx_json = fs.readFileSync(
  path.join(getAppRootDir(), sbom_filepath, 'bom.cyclonedx.json'),
  'utf-8'
);
const cyclonedx_xml = fs.readFileSync(
  path.join(getAppRootDir(), sbom_filepath, 'bom.cyclonedx.xml'),
  'utf-8'
);

//SPDX JSON
const spdxJsonResult: Package[] = parse(spdx_json, SbomFormat.SPDX_JSON);
let numComponentsSpdxJson = 4;
test('Test 1: spdx json: parses all packages', () => {
  expect(spdxJsonResult.length).toEqual(numComponentsSpdxJson);
});
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

test('Test 2: spdx json: parses accurately', () => {
  expect(spdxJsonResult).toStrictEqual(packages);
});

//SPDX Tag/Value
const spdxResult: Package[] = parse(spdx, SbomFormat.SPDX_TAGVALUE);
let numComponentsSpdx = 1;
test('Test 1: spdx json: parses all packages', () => {
  expect(spdxResult.length).toEqual(numComponentsSpdx);
});
let packages2: Package[] = [
  {
    consRisk: null,
    cpeName: null,
    highestRisk: null,
    ref: 'SPDXRef-Package',
    impact: null,
    likelihood: null,
    name: 'glibc',
    purl: null,
    version: '2.11.1',
  },
];

test('Test 2: spdx json: parses accurately', () => {
  expect(spdxResult).toStrictEqual(packages2);
});

//CycloneDx JSON
const cycloneJsonResult: Package[] = parse(
  cyclonedx_json,
  SbomFormat.CYCLONEDX_JSON
);
let numComponentsJson = 62;
test('Test 2: cyclonedx json: parses all packages', () => {
  expect(cycloneJsonResult.length).toEqual(numComponentsJson);
});
let package1: Package = {
  consRisk: null,
  cpeName: null,
  highestRisk: null,
  ref: 'pkg:composer/asm89/stack-cors@1.3.0',
  impact: null,
  likelihood: null,
  name: 'stack-cors',
  purl: 'pkg:composer/asm89/stack-cors@1.3.0',
  version: '1.3.0',
};
let package2: Package = {
  consRisk: null,
  cpeName: null,
  highestRisk: null,
  ref: 'pkg:composer/league/commonmark@1.6.6',
  impact: null,
  likelihood: null,
  name: 'commonmark',
  purl: 'pkg:composer/league/commonmark@1.6.6',
  version: '1.6.6',
};
let package3: Package = {
  consRisk: null,
  cpeName: null,
  highestRisk: null,
  ref: 'pkg:composer/voku/portable-ascii@1.5.6',
  impact: null,
  likelihood: null,
  name: 'portable-ascii',
  purl: 'pkg:composer/voku/portable-ascii@1.5.6',
  version: '1.5.6',
};
test('Test 3: cyclonedx json: parses accurately', () => {
  expect(cycloneJsonResult).toContainEqual(package1);
  expect(cycloneJsonResult).toContainEqual(package2);
  expect(cycloneJsonResult).toContainEqual(package3);
});

//CycloneDx XML
const cycloneXmlResult: Package[] = parse(
  cyclonedx_xml,
  SbomFormat.CYCLONEDX_XML
);
let numComponentsXml = 840;
test('Test 4: cyclonedx xml: parses all packages', () => {
  expect(cycloneXmlResult.length).toEqual(numComponentsXml);
});
let package4: Package = {
  consRisk: null,
  cpeName: null,
  highestRisk: null,
  ref: 'pkg:npm/body-parser@1.19.0',
  impact: null,
  likelihood: null,
  name: 'body-parser',
  purl: 'pkg:npm/body-parser@1.19.0',
  version: '1.19.0',
};
let package5: Package = {
  consRisk: null,
  cpeName: null,
  highestRisk: null,
  ref: 'pkg:npm/supports-color@6.1.0',
  impact: null,
  likelihood: null,
  name: 'supports-color',
  purl: 'pkg:npm/supports-color@6.1.0',
  version: '6.1.0',
};
let package6: Package = {
  consRisk: null,
  cpeName: null,
  highestRisk: null,
  ref: 'pkg:npm/uglify-to-browserify@1.0.2',
  impact: null,
  likelihood: null,
  name: 'uglify-to-browserify',
  purl: 'pkg:npm/uglify-to-browserify@1.0.2',
  version: '1.0.2',
};
test('Test 5: cyclonedx xml: parses accurately', () => {
  expect(cycloneXmlResult).toContainEqual(package4);
  expect(cycloneXmlResult).toContainEqual(package5);
  expect(cycloneXmlResult).toContainEqual(package6);
});
