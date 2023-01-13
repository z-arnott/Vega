import { Package, SbomFormat } from '../utils/types.utils';
import { XMLParser } from 'fast-xml-parser';

export { parse };

/****************** PARSER CONTEXT PUBLIC FUNCTIONS **********************/
//Parses one SBOM, query, returns list of Vulnerabilities
function parse(sbom: any, strategy: SbomFormat): Package[] {
  //Set strategy
  let parser: ParsingStrategy = parsingStrategies[strategy];
  //Parse file
  return parser(sbom);
}

/****************** PARSING STRATEGY INTERFACE **********************/
interface ParsingStrategy {
  (sbom: string): Package[];
}

//Parser instances
let spdxJsonParser: ParsingStrategy;
let spdxTagValueParser: ParsingStrategy;
let cyclonedxJsonParser: ParsingStrategy;
let cyclonedxXmlParser: ParsingStrategy;

//Cleaner implementaions
spdxJsonParser = function (sbom): Package[] {
  let packages: Package[] = [];
  let sbomPackages: any = JSON.parse(sbom).packages; //get all packages
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
      version: pkg.versionInfo,
    };

    //Get External Reference locators
    if (pkg.hasOwnProperty('externalRefs')) {
      for (let extRef of pkg.externalRefs) {
        if (extRef.referenceType == 'purl' && p.purl == undefined) {
          p.purl = extRef.referenceLocator;
          break; //stop if EITHER cpe or purl found
        }
        if (extRef.referenceType.includes('cpe') && p.cpeName == undefined) {
          p.cpeName = extRef.referenceLocator;
          break; //stop if EITHER cpe or purl found
        }
      }
    }
    packages.push(p);
  });
  return packages;
};

spdxTagValueParser = function (sbom): Package[] {
  let packages: Package[] = [];
  let sbomArray = sbom.toString().split(/\n[#]+.*(?:Package).*\n/gm); //split string by packages
  sbomArray.shift(); //remove header info before packages
  for (let str of sbomArray) {
    let tags = str.split('\n');
    let name: string = '';
    let id: string = '';
    let cpe = undefined;
    let purl = undefined;
    let version = undefined;

    for (let line of tags) {
      if (line != '') {
        const [tag, ...rest] = line.split(':');
        const value = rest.join(':').trim();
        if (tag == 'SPDXID') {
          id = value;
        } else if (tag == 'PackageName') {
          name = value;
        } else if (tag == 'PackageVersion') {
          version = value;
        } else if (
          tag == 'ExternalRef' &&
          value.includes('cpe') &&
          cpe == undefined
        ) {
          cpe = value.split(' ')[2];
        } else if (
          tag == 'ExternalRef' &&
          value.includes('purl') &&
          purl == undefined
        ) {
          purl = value.split(' ')[2];
        }
        if (tag.includes('#')) {
          break;
        } //end of package
      }
    }
    let p: Package = {
      name: name,
      id: id,
      purl: purl,
      cpeName: cpe,
      impact: undefined,
      consRisk: undefined,
      highestRisk: undefined,
      likelihood: undefined,
      version: version,
    };
    packages.push(p);
  }
  return packages;
};

/* Create a list of Packages from JSON package list in CycloneDX format */
function cyclonedxGetPackages(sbomPackages: any): Package[] {
  let packages: Package[] = [];
  sbomPackages.forEach(function (pkg: any) {
    let p: Package = {
      name: pkg.name,
      id: pkg['bom-ref'],
      purl: undefined,
      cpeName: undefined,
      impact: undefined,
      consRisk: undefined,
      highestRisk: undefined,
      likelihood: undefined,
      version: pkg.version,
    };
    //Get External Reference locators
    if (pkg.hasOwnProperty('purl')) {
      p.purl = pkg.purl;
    }
    if (pkg.hasOwnProperty('cpe')) {
      p.cpeName = pkg.cpe;
    }
    packages.push(p);
  });
  return packages;
}

cyclonedxXmlParser = function (sbom): Package[] {
  //Convert xml --> json
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '',
  });
  let sbomObj = parser.parse(sbom);
  //Trim sbom to only package list
  let sbomPackages: any = sbomObj.bom.components.component;
  return cyclonedxGetPackages(sbomPackages);
};

cyclonedxJsonParser = function (sbom): Package[] {
  //Trim sbom to only package list
  let sbomPackages: any = JSON.parse(sbom).components;
  return cyclonedxGetPackages(sbomPackages);
};

/* Register parsing strategies here */
let parsingStrategies = {
  [SbomFormat.SPDX_JSON]: spdxJsonParser,
  [SbomFormat.SPDX_TAGVALUE]: spdxTagValueParser,
  [SbomFormat.CYCLONEDX_JSON]: cyclonedxJsonParser,
  [SbomFormat.CYCLONEDX_XML]: cyclonedxXmlParser,
};
