import {parse} from '@services/parserContext.services';
import fs from 'fs';
import { Package, SbomFormat } from '@utils/types.utils';
import * as react_spdx_json from 'sbom_examples/demo_tests/spdx/react.spdx.json';
import * as react_cyclonedx_json from 'sbom_examples/demo_tests/cycloneDX/cyclonedx_react.json';


//Setup


//Test 1: SPDX JSON
let expectedResult1: Package =
      {
            consRisk: undefined,
            cpeName: "cpe:2.3:a:*:ws:8.9.0:*:*:*:*:*:*:*",
            highestRisk: undefined,
            id: "SPDXRef-Package-npm-ws-cd7a4f1b61a45b20",
            impact: undefined,
            likelihood: undefined,
            name: "ws",
            purl: "pkg:npm/ws@8.9.0",
      };
test('Test 1: SPDX json parser ', () => {
      expect(parse(react_spdx_json, SbomFormat.SPDX_JSON)).toContainEqual(expectedResult1);
});

//Test 2: CycloneDx JSON
let expectedResult2: Package =
      {
            consRisk: undefined,
            cpeName: "cpe:2.3:a:ws:ws:8.9.0:*:*:*:*:*:*:*",
            highestRisk: undefined,
            id: "pkg:npm/ws@8.9.0?package-id=cd7a4f1b61a45b20",
            impact: undefined,
            likelihood: undefined,
            name: "ws",
            purl: "pkg:npm/ws@8.9.0",
      };
test('Test 2: CycloneDX json parser ', () => {
      expect(parse(react_cyclonedx_json, SbomFormat.CYCLONEDX_JSON)).toContainEqual(expectedResult2);
});

//Test 3: CycloneDx XML
const react_cyclonedx_xml = fs.readFileSync('/home/zobuntu/Documents/GitHub/Vega/dist/test/unit/test.xml');
let expectedResult3: Package =
      {
            consRisk: undefined,
            cpeName: "cpe:2.3:a:ws:ws:8.9.0:*:*:*:*:*:*:*",
            highestRisk: undefined,
            id: "pkg:npm/ws@8.9.0?package-id=cd7a4f1b61a45b20",
            impact: undefined,
            likelihood: undefined,
            name: "ws",
            purl: "pkg:npm/ws@8.9.0",
      };
test('Test 3:  ', () => {
      expect(parse(react_cyclonedx_xml, SbomFormat.CYCLONEDX_XML)).toContainEqual(expectedResult3);
});
