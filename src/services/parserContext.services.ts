import { Package, SbomFormat } from '../utils/types.utils';
import { XMLParser } from 'fast-xml-parser';

export { parse };

/****************** PARSER CONTEXT PUBLIC FUNCTIONS **********************/
/**
 * Parse one SBOM, query, returns list of Vulnerabilities
 * @param sbom a software bill of materials (SBOM)
 * @param strategy the parsing strategy taken on sbom
 * @returns  a list of packages contained in sbom
 */
function parse(sbom: string, strategy: SbomFormat): Package[] {
  //Set strategy
  let parser: ParsingStrategy = parsingStrategies[strategy];
  //Parse file
  return parser(sbom);
}

/****************** PARSING STRATEGY INTERFACE **********************/
/**
 * A parsing strategy is the strategy taken to extract packages from
 * a Software Bill of Materials (SBOM),
 * dependant on SBOM format
 *
 * @interface ParsingStrategy
 */
interface ParsingStrategy {
  (sbom: string): Package[];
}

//Parser instances
let spdxJsonParser: ParsingStrategy;
let spdxTagValueParser: ParsingStrategy;
let cyclonedxJsonParser: ParsingStrategy;
let cyclonedxXmlParser: ParsingStrategy;

/**
 * Parsing Strategy implementation used to parse
 * a Software Bill of Materials (SBOM)
 * with SPDX specifications, in JSON format
 * @param sbom the SBOM string
 * @returns list of packages contained in sbom
 */
spdxJsonParser = function (sbom): Package[] {
  let packages: Package[] = [];
  let sbomPackages: any = JSON.parse(sbom).packages; //get all packages
  sbomPackages.forEach(function (pkg: any) {
    let p: Package = {
      name: pkg.name,
      ref: pkg.SPDXID,
      purl: null,
      cpeName: null,
      consRisk: null,
      highestRisk: null,
      version: null,
    };

    //Get External Reference locators
    if (pkg.hasOwnProperty('externalRefs')) {
      for (let extRef of pkg.externalRefs) {
        if (extRef.referenceType == 'purl' && p.purl == null) {
          p.purl = extRef.referenceLocator;
          break; //stop if EITHER cpe or purl found
        }
        if (extRef.referenceType.includes('cpe') && p.cpeName == null) {
          p.cpeName = extRef.referenceLocator;
          break; //stop if EITHER cpe or purl found
        }
      }
    }
    //Get Version
    if (pkg.hasOwnProperty('versionInfo')) {
      p.version = pkg.versionInfo;
    }
    packages.push(p);
  });
  return packages;
};

/**
 * Parsing Strategy implementation used to parse
 * a Software Bill of Materials (SBOM)
 * with SPDX specifications, in TAG/VALUE format
 * @param sbom the SBOM string
 * @returns list of packages contained in sbom
 */
spdxTagValueParser = function (sbom): Package[] {
  let packages: Package[] = [];
  let sbomArray = sbom.toString().split(/\n[#]+.*(?:Package).*\n/gm); //split string by packages
  sbomArray.shift(); //remove header info before packages
  for (let str of sbomArray) {
    let tags = str.split('\n');
    let name: string = '';
    let id: string = '';
    let cpe = null;
    let purl = null;
    let version = null;

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
          cpe == null
        ) {
          cpe = value.split(' ')[2];
        } else if (
          tag == 'ExternalRef' &&
          value.includes('purl') &&
          purl == null
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
      ref: id,
      purl: purl,
      cpeName: cpe,
      consRisk: null,
      highestRisk: null,
      version: version,
    };
    packages.push(p);
  }
  return packages;
};

function cyclonedxGetPackages(sbomPackages: any): Package[] {
  let packages: Package[] = [];
  sbomPackages.forEach(function (pkg: any) {
    let p: Package = {
      name: pkg.name,
      ref: pkg['bom-ref'],
      purl: null,
      cpeName: null,
      consRisk: null,
      highestRisk: null,
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

/**
 * Parsing Strategy implementation used to parse
 * a Software Bill of Materials (SBOM)
 * with CYCLONEDX specifications, in XML format
 * @param sbom the SBOM string
 * @returns list of packages contained in sbom
 */
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

/**
 * Parsing Strategy implementation used to parse
 * a Software Bill of Materials (SBOM)
 * with CYCLONEDX specifications, in JSON format
 * @param sbom the SBOM string
 * @returns list of packages contained in sbom
 */
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
