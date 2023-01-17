import { supabase } from './supabase';
import { Package, Vulnerability } from './types.utils';
import { logger } from '@utils/logger.utils';

/****************** PUBLIC API **********************/
//Read all packages in a session
export async function readAllPackages(sessionid: number) {
  let { data, error } = await supabase //common syntax on JS: const {data,error} = await...
    .from('packages')
    .select('*') //values are outputted first in, last out
    .eq('sessionid', sessionid);
  let packages: Package[] = [];

  if (data) {
    for (let pkg of data) {
      packages.push(dbPkgToPkg(pkg));
    }
  } else {
    logger.error(error);
  }
  console.log(packages);
  return packages;
}

//Read a package by package reference
export async function readPackage(packageRef: string, sessionID: number) {
  let { data, error } = await supabase
    .from('packages')
    .select('*') //values are outputted first in, last out
    .eq('sessionid', sessionID)
    .eq('package_ref', packageRef);

  if (data) {
    return dbPkgToPkg(data[0]);
  } else if (error) {
    logger.error(error.message);
    return error;
  }
}

//Write Package, updates if entry exists in database, inserts otherwise
export async function writePackage(pkg: Package, sessionId: number) {
  let { data, error } = await supabase
    .from('packages')
    .select('*')
    .eq('sessionid', sessionId)
    .eq('package_ref', pkg.ref);

  if (data) {
    if (data.length == 0) {
      //INSERT
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
    } else {
      //UPDATE
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
  }
  if (error) {
    logger.error(error.message);
  }
}

//Read all vulnerabilities in one session
export async function readVulnBySession(sessionId: number) {
  let { data, error } = await supabase
    .from('vulnerabilities')
    .select('*,junction!inner(packageid,packages!inner(package_ref))')
    .eq('junction.packages.sessionid', sessionId);

  let cves: Vulnerability[] = [];
  if (data) {
    for (let v of data) {
      cves.push(
        //map database result to Vulnerability object
        {
          cveId: v.cveidstring,
          packageRef: v.junction.packages.package_ref,
          impact: v.impact,
          likelihood: v.likelihood,
          risk: v.risk,
          cvss2: v.cvss_vector,
        }
      );
    }
    return cves;
  } else if (error) {
    logger.error(error.message);
    return error;
  }
}

//Read all vulnerabilites in one package
export async function readCvesByPkgID(packageRef: string, sessionId: number) {
  const { data, error } = await supabase
    .from('vulnerabilities')
    .select('*,junction!inner(packageid,packages!inner(package_ref))')
    .eq('junction.packages.package_ref', packageRef);
  let cves: Vulnerability[] = [];
  if (data) {
    for (let v of data) {
      cves.push(
        //map database result to Vulnerability object
        {
          cveId: v.cveidstring,
          packageRef: v.junction.packages.package_ref,
          impact: v.impact,
          likelihood: v.likelihood,
          risk: v.risk,
          cvss2: v.cvss_vector,
        }
      );
    }
    return cves;
  } else if (error) {
    logger.error(error.message);
    return error;
  }
}

//Write Vulnerability
export async function writeCve(cve: Vulnerability) {
  let { data, error } = await supabase
    .from('vulnerabilities')
    .select('*')
    .eq('cveidstring', cve.cveId);

  if (data) {
    if (data.length == 0) {
      //INSERT
      let { status, error } = await supabase.from('vulnerabilities').insert({
        //append necessary housekeeping info for database
        risk: cve.risk,
        likelihood: cve.likelihood,
        impact: cve.impact,
        cveidstring: cve.cveId,
      });
      if (error) {
        logger.error(error.message);
      }
      return status;
    } else {
      //UPDATE
      let { status, error } = await supabase
        .from('vulnerabilities')
        .update({
          //append necessary housekeeping info for database
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
  }
  if (error) {
    logger.error(error.message);
  }
}

/****************** READ PACKAGES **********************/
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
    return error;
  }
}

/****************** WRITE PACKAGE**********************/
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

/****************** WRITE VULNERABILITY **********************/
//Function #5: Write Request (Vulnerability) - Single or Multiple
async function writeVuln(DBVulnerabilityInput: any) {
  let { status } = await supabase
    .from('vulnerabilities')
    .insert(DBVulnerabilityInput);
  return status;
}

async function DeleteVuln(cveid: number) {
  let { status } = await supabase
    .from('vulnerabilities')
    .delete()
    .eq('cveid', cveid);
  return status;
}

/****************** PURGE ALL **********************/
//phase 2 - create a purge all function

/****************** UPDATE DATA **********************/
//Update package by package id
async function updatePackage(packageid: number, DBPackage: any) {
  let { status } = await supabase
    .from('packages')
    .update(DBPackage)
    .eq('packageid', packageid);
  return status;
}

//Update vulnerability by cveid
async function updateVuln(cveid: number, DBVulnerabilityInput: any) {
  let { status } = await supabase
    .from('vulnerabilities')
    .update(DBVulnerabilityInput)
    .eq('cveid', cveid);
  return status;
}
