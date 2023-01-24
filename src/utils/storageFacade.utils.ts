import { supabase } from './supabase';
import {
  Package,
  Vulnerability,
  PackageViewParam,
  VulnerabilityViewParam,
  DisplayPackage,
  severityRating,
  SEVERITY_TO_RISK_CONVERSION
} from './types.utils';
import { logger } from '@utils/logger.utils';

const DEFAULT_PACAKGE_SORT = PackageViewParam.NAME;
const DEFAULT_CVE_SORT = VulnerabilityViewParam.CVEID;

/****************** PUBLIC API: PACKAGES **********************/
/**
 * Read all packages in a session
 * @param sessionid associated with one user
 * @returns list of packages for given sessionid, returns empty if no matching packages present in DB
 */
export async function readAllPackages(sessionid: number) {
  let { data, error } = await supabase //common syntax on JS: const {data,error} = await...
    .from('packages')
    .select('*') //values are outputted first in, last out
    .eq('sessionid', sessionid);

  let packages: Package[] = [];

  if (error) {
    logger.error(error);
  } else if (data) {
    for (let pkg of data) {
      packages.push(dbPkgToPkg(pkg));
    }
  }

  return packages;
}

/**
 * Read a package by package reference string
 * @param packageRef unique string ID retrieved from user-uploaded software bill of materials
 * @param sessionId associated with one user
 * @returns package if found in DB, null otherwise
 */
export async function readPackage(packageRef: string, sessionId: number) {
  let { data, error } = await supabase
    .from('packages')
    .select('*') //values are outputted first in, last out
    .eq('sessionid', sessionId)
    .eq('package_ref', packageRef);

  if (error) {
    logger.error(error.message);
    return null;
  } else if (data) {
    if (data.length == 0) {
      //No entry found
      logger.error('Storage Facade: Package "' + packageRef + '" not found');
      return null;
    } else if (data.length > 1) {
      //Duplicates (how should we handle?)
      logger.error(
        'Storage Facade: Duplicate packages found for "' +
          packageRef +
          '" in session ' +
          sessionId
      );
      return dbPkgToPkg(data[0]);
    } else {
      return dbPkgToPkg(data[0]);
    }
  }
}

/**
 * Write Package, updates if entry exists in database, inserts otherwise
 * @param pkg to write to database
 * @param sessionId associated with one user
 * @returns supabase write status
 */
export async function writePackage(pkg: Package, sessionId: number) {
  let { data, error, status } = await supabase
    .from('packages')
    .select('*')
    .eq('sessionid', sessionId)
    .eq('package_ref', pkg.ref);

  if (error) {
    logger.error(error.message);
  } else if (data) {
    if (data.length == 0) {
      //INSERT
      return insertPackage(pkg, sessionId);
    } else {
      //UPDATE
      return updatePackage(pkg, sessionId);
    }
  }
  return status;
}


/**
 * Read packages for Dashboard
 * @param sessionid unique user session number
 * @param sortParam to sort data
 * @returns list of DisplayPackages
 */
 export async function readPacakgesSorted(
  sessionid: number,
  sortParam: PackageViewParam
) {
  let packages: DisplayPackage[] = [];

  let col = mapPkgParamToColumn(sortParam);
  if (sortParam == PackageViewParam.NUMBER_OF_VULNERABILITIES) {
    col = 'junction';
  }

  let { data, error } = await supabase //common syntax on JS: const {data,error} = await...
    .from('packages')
    .select('*,junction!inner(vulnerabilities!inner(*))')
    .eq('sessionid', sessionid)
    .order(col);

  if (error) {
    logger.error(error);
  } else if (data) {
    for (let pkg of data) {
      let cves: Vulnerability[] = [];
      for (let v of pkg.junction) {
        cves.push(
          //map database result to Vulnerability object
          {
            cveId: v.vulnerabilities.cveidstring,
            packageRef: pkg.package_ref,
            impact: v.vulnerabilities.impact,
            likelihood: v.vulnerabilities.likelihood,
            risk: v.vulnerabilities.risk,
            cvss2: v.vulnerabilities.cvss_vector,
          }
        );
      }
      packages.push({
        //map database result to Dashboard View Package
        Componenent_name: pkg.name,
        Component_ref: pkg.package_ref,
        Number_of_Vulnerabilities: pkg.junction.length,
        Highest_Risk: pkg.highestRisk,
        Consolidated_Risk: pkg.consrisk,
        Vulnerabilities: cves,
      });
    }
  }
  console.log(packages);
  return packages;
}

/****************** PUBLIC API: VULNERABILITIES **********************/
/**
 * Read all vulnerabilites in one package
 * @param packageRef unique string ID retrieved from user-uploaded software bill of materials
 * @param sessionId associated with one user
 * @returns list of packages, empty list if none matching are present in DB
 */
export async function readVulnsByPkg(ref: string, sessionId: number) {
  const { data, error } = await supabase
    .from('vulnerabilities')
    .select(
      '*,junction!inner(packageid,packages!inner(package_ref, sessionid))'
    )
    .eq('junction.packages.package_ref', ref)
    .eq('junction.packages.sessionid', sessionId);
  let cves: Vulnerability[] = [];

  if (error) {
    logger.error(error.message);
  } else if (data) {
    for (let v of data) {
      cves.push(
        //map database result to Vulnerability object
        {
          cveId: v.cveidstring,
          packageRef: ref,
          impact: v.impact,
          likelihood: v.likelihood,
          risk: v.risk,
          cvss2: v.cvss_vector,
        }
      );
    }
  }
  return cves;
}

/**
 * Write Package, updates if entry exists in database, inserts otherwise
 * @param cve to write
 * @param sessionId associated with one user
 * @returns supabase write status
 */
export async function writeVuln(cve: Vulnerability, sessionId: number) {
  let { data, error } = await supabase
    .from('vulnerabilities')
    .select('*')
    .eq('cveidstring', cve.cveId);

  if (error) {
    logger.error(error.message);
    return error;
  } else if (data) {
    if (data.length == 0) {
      //INSERT
      return insertVuln(cve, sessionId);
    } else {
      //UPDATE
      return updateVuln(cve, sessionId);
    }
  }
  return 400;
}

/**
 * Read all vulnerabilities in one session
 * @param sessionId associated with one user
 * @returns list of vulnerabilities, empty list if none matching present in DB
 */
 export async function readVulnsBySession(sessionId: number) {
  return readVulnerabilitiesSorted(sessionId, DEFAULT_CVE_SORT);
}

export async function readVulnerabilitiesSorted(
  sessionId: number,
  sortParam: VulnerabilityViewParam
) {
  
  return readVulnerabilitiesFiltered(sessionId, sortParam, VulnerabilityViewParam.RISK, severityRating.LOW, severityRating.CRITICAL);
}

/**
 * Read packages for Dashboard
 * @param sessionid unique user session number
 * @param sortParam to sort data
 * @returns list of DisplayPackages
 */
 export async function readVulnerabilitiesFiltered(
  sessionId: number,
  sortParam: VulnerabilityViewParam, 
  filterParam: VulnerabilityViewParam,
  lowerLimit:severityRating,
  upperLimit:severityRating,
) {
  let sortCol = mapVulnParamToColumn(sortParam);
  let filterCol = mapVulnParamToColumn(filterParam);
  if(filterParam == VulnerabilityViewParam.RISK){
    lowerLimit *= SEVERITY_TO_RISK_CONVERSION;
    upperLimit *= SEVERITY_TO_RISK_CONVERSION;
  }
  let { data, error } = await supabase
    .from('vulnerabilities')
    .select(
      '*,junction!inner(packageid,packages!inner(sessionid, package_ref))'
    )
    .eq('junction.packages.sessionid', sessionId)
    .gte(filterCol, lowerLimit)
    .lt(filterCol, upperLimit)
    .order(sortCol);

  let cves: Vulnerability[] = [];
  if (error) {
    logger.error(error.message);
  } else if (data) {
    for (let v of data) {
      cves.push(
        //map database result to Vulnerability object
        {
          cveId: v.cveidstring,
          packageRef: v.junction[0].packages.package_ref,
          impact: v.impact,
          likelihood: v.likelihood,
          risk: v.risk,
          cvss2: v.cvss_vector,
        }
      );
    }
  }

  return cves;
}
/******************PACKAGE HELPERS**********************/
//Insert package by package id
async function insertPackage(pkg: Package, sessionId: number) {
  let { status, error } = await supabase.from('packages').insert({
    //append necessary housekeeping info for database
    name: pkg.name,
    packageversion: pkg.version,
    consrisk: pkg.consRisk,
    impact: pkg.impact,
    likelihood: pkg.likelihood,
    highestrisk: pkg.highestRisk,
    purl: pkg.purl,
    cpename: pkg.cpeName,
    sessionid: sessionId,
    package_ref: pkg.ref,
  });
  if (error) {
    logger.error(error.message);
  }
  return status;
}

async function updatePackage(pkg: Package, sessionId: number) {
  let { status, error } = await supabase
    .from('packages')
    .update({
      //append necessary housekeeping info for database
      name: pkg.name,
      packageversion: pkg.version,
      consrisk: pkg.consRisk,
      impact: pkg.impact,
      likelihood: pkg.likelihood,
      highestrisk: pkg.highestRisk,
      purl: pkg.purl,
      cpename: pkg.cpeName,
    })
    .eq('sessionid', sessionId)
    .eq('package_ref', pkg.ref);
  if (error) {
    logger.error(error.message);
  }
  return status;
}

async function deletePackage(packageid: number) {
  const { status } = await supabase
    .from('packages')
    .delete()
    .eq('packageid', packageid);
  return status;
}

//Convert database data into Package object
function dbPkgToPkg(pkg: any): Package {
  let p = {
    ref: pkg.package_ref,
    name: pkg.name,
    version: pkg.packageversion,
    highestRisk: pkg.highestrisk,
    purl: pkg.purl,
    cpeName: pkg.cpename,
    impact: pkg.impact,
    consRisk: pkg.consrisk,
    likelihood: pkg.likelihood,
  };
  return p;
}

async function readPackageById(sessionid: number, packageid: number) {
  let { data, error } = await supabase //common syntax on JS: const {data,error} = await...
    .from('packages')
    .select('*') //values are outputted first in, last out
    .eq('sessionid', sessionid)
    .eq('packageid', packageid);
  if (data) {
    return dbPkgToPkg(data);
  } else if (error) {
    logger.error(error.message);
    return null;
  }
}

/****************** VULNERABILITY HELPERS **********************/
//Function #5: Write Request (Vulnerability) - Single or Multiple
async function insertVuln(cve: Vulnerability, sessionId: number) {
  let { data, status, error } = await supabase
    .from('vulnerabilities')
    .insert({
      likelihood: cve.likelihood,
      impact: cve.impact,
      risk: cve.risk,
      cveidstring: cve.cveId,
      cvss_vector: cve.cvss2,
    })
    .select('id');

  if (error) {
    logger.error(error.message);
  }
  if (data) {
    let vulnerabilityTableId = data[0].id; //vulnerability PRIMARY key in vulnerability table
    return createJunctionEntry(vulnerabilityTableId, cve.packageRef, sessionId);
  }
  return status;
}

async function createJunctionEntry(
  cveTableId: number,
  packageRef: string,
  sessionId: number
) {
  //get packageId
  let { data, error, status } = await supabase
    .from('packages')
    .select('packageid')
    .eq('package_ref', packageRef)
    .eq('sessionid', sessionId);

  if (error) {
    logger.error(error.message);
  } else if (data) {
    if (data.length == 0) {
      //No associate package (how should we handle?)
      logger.error('Storage Facade: Package "' + packageRef + '" not found');
      return null;
    } else {
      //Link CVE to its package in junction table
      let { status, error } = await supabase.from('junction').insert({
        packageid: data[0].packageid,
        cveid: cveTableId,
      });
    }
  }
  return status;
}

//Update vulnerability by cveid
async function updateVuln(cve: Vulnerability, sessionId: number) {
  let { status, error } = await supabase
    .from('vulnerabilities')
    .update({
      risk: cve.risk,
      likelihood: cve.likelihood,
      impact: cve.impact,
    })
    .eq('cveidstring', cve.cveId);

  if (error) {
    logger.error(error.message);
  }
  return status;
}

/************* DASHBOARD HELPERS *******************/
function mapPkgParamToColumn(sortParam: PackageViewParam): string {
  let col: string;
  switch (sortParam) {
    case PackageViewParam.NAME: {
      col = 'name';
      break;
    }
    case PackageViewParam.CONSOLIDATED_RISK: {
      col = 'consrisk';
      break;
    }
    case PackageViewParam.HIGHEST_RISK: {
      col = 'highestrisk';
      break;
    }
    case PackageViewParam.COMPONENT_REF: {
      col = 'package_ref';
      break;
    }
    default: {
      col = 'unknown';
    }
  }
  return col;
}

function mapVulnParamToColumn(sortParam: VulnerabilityViewParam): string {
  let col: string;
  switch (sortParam) {
    case VulnerabilityViewParam.CVEID: {
      col = 'cveidstring';
      break;
    }
    case VulnerabilityViewParam.SEVERITY: {
      col = 'severity';
      break;
    }
    case VulnerabilityViewParam.RISK: {
      col = 'risk';
      break;
    }
    case VulnerabilityViewParam.IMPACT: {
      col = 'impact';
      break;
    }
    case VulnerabilityViewParam.LIKELIHOOD: {
      col = 'likelihood';
      break;
    }
    default: {
      col = 'unknown';
    }
  }
  return col;
}

/****************** PURGE ALL **********************/
//TODO: iteration 3
