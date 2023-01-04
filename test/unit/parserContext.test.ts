import {parse} from '@services/parserContext.services';
import * as react_spdx_json from 'sbom_examples/demo_tests/spdx/react.spdx.json';
import { Package, SbomFormat } from '@utils/types.utils';

//Setup
//console.log(JSON.stringify(json, null, 2));
//Test 1:
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