import { supabase } from './supabase';
import { Package, Vulnerability } from './types.utils';
import { logger } from '@utils/logger.utils';

/****************** PUBLIC API **********************/
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
 * Read all vulnerabilities in one session
 * @param sessionId associated with one user
 * @returns list of vulnerabilities, empty list if none matching present in DB
 */
export async function readVulnsBySession(sessionId: number) {
  let { data, error } = await supabase
    .from('vulnerabilities')
    .select('*,junction!inner(packageid,packages!inner(package_ref))')
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

/**
 * Read all vulnerabilites in one package
 * @param packageRef unique string ID retrieved from user-uploaded software bill of materials
 * @param sessionId associated with one user
 * @returns list of packages, empty list if none matching are present in DB
 */
export async function readVulnsByPkg(packageRef: string, sessionId: number) {
  const { data, error } = await supabase
    .from('vulnerabilities')
    .select('*,junction!inner(packageid,packages!inner(package_ref))')
    .eq('junction.packages.package_ref', packageRef);
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

//Function #4: Write Single or Many Request (Package)
async function writePackageByVulType(DBPackage: any) {
  let { status } = await supabase.from('packages').insert(DBPackage);
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
    let vulnerabilityTableId = data[0].id; //row ID in database
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

async function DeleteVuln(cveid: number) {
  let { status } = await supabase
    .from('vulnerabilities')
    .delete()
    .eq('cveid', cveid);
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

/****************** PURGE ALL **********************/
//TODO: iteration 3
