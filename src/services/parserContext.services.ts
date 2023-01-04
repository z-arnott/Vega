import { Package, SbomFormat } from '@utils/types.utils';
import { pbkdf2Sync } from 'crypto';

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

    //Get External Reference locators
    if (pkg.hasOwnProperty('externalRefs')) {
      for(let extRef of pkg.externalRefs){
        if (extRef.referenceType == 'purl') {
          p.purl = extRef.referenceLocator;
          //break here? then we get EITHER cpe or purl
        }
        if (extRef.referenceType.startsWith('cpe')) {
          p.cpeName = extRef.referenceLocator;
          //break here? then we get EITHER cpe or purl
        }
    }
    packages.push(p);
  }})
  return packages;
};

spdxTagValueParser = function (sbom): Package[] {
  return [];
};
cyclonedxJsonParser = function (sbom): Package[] {
  return [];
};
cyclonedxXmlParser = function (sbom): Package[] {
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

    //Get External Reference locators
    if (pkg.hasOwnProperty('externalRefs')) {
      for(let extRef of pkg.externalRefs){
        if (extRef.referenceType == 'purl') {
          p.purl = extRef.referenceLocator;
          //break here? then we get EITHER cpe or purl
        }
        if (extRef.referenceType.startsWith('cpe')) {
          p.cpeName = extRef.referenceLocator;
          //break here? then we get EITHER cpe or purl
        }
    }
    packages.push(p);
  }})
  return packages;
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

export {parse}
