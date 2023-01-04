import { Package, SbomFormat } from '@utils/types.utils';

/****************** PARSING STRATEGY INTERFACE **********************/
interface ParsingStrategy {
  (sbom: any): Package[];
}

//Parser instances
let spdxJsonParser: ParsingStrategy;
let spdxTagValueParser: ParsingStrategy;
let cyclonedxJsonParser: ParsingStrategy;
let cyclonedxXmlParser: ParsingStrategy;

//Cleaner implementaions
spdxJsonParser = function (sbom): Package[] {
  let packages: Package[] = [];
  let sbomPackages: any = sbom.packages; //get all packages

  //Create Vulnerability for each cve in response
  sbomPackages.forEach(function (pkg: any) {
    let p: Package = {
      name: pkg.name,
      id: pkg.SPDXID,
      purl: undefined,
      cpeName: undefined,
      impact: undefined,
      consRisk: undefined,
      highestRisk: undefined,
      likelihood: undefined,
    };

    //Get correct CVSS version
    if (pkg.hasOwnProperty('externalRefs')) {
      if (pkg.referenceType == 'purl') {
        p.purl = pkg.referenceLocator;
      } else if (pkg.referenceType == '') {
      }
    }
  });
  return [];
};

spdxTagValueParser = function (sbom): Package[] {
  return [];
};
cyclonedxJsonParser = function (sbom): Package[] {
  return [];
};
cyclonedxXmlParser = function (sbom): Package[] {
  return [];
};

/* Register parsing strategies here */
let parsingStrategies = {
  [SbomFormat.SPDX_JSON]: spdxJsonParser,
  [SbomFormat.SPDX_TAGVALUE]: spdxTagValueParser,
  [SbomFormat.CYCLONEDX_JSON]: cyclonedxJsonParser,
  [SbomFormat.CYCLONEDX_XML]: cyclonedxJsonParser,
};

/****************** PARSER CONTEXT PUBLIC FUNCTIONS **********************/
//Parses one SBOM, query, returns list of Vulnerabilities
function parse(sbom: any, strategy: SbomFormat): Package[] {
  //Set strategy
  let parser: ParsingStrategy = parsingStrategies[strategy];
  //Parse file
  return parser(sbom);
}
