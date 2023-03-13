import {
  Package,
  Query,
  VulDatabase,
  Vulnerability,
} from '../utils/types.utils';
import dotenv from 'dotenv';

dotenv.config();
const API_KEY = process.env.API_KEY as string;
const AUTH = process.env.AUTHORIZATION as string;

/**
 * Given a package, send a
 * @param pkg a package object as stored in the packages database
 */
function buildQuery(pkg: Package) {
  let query: any = {};
  if (pkg.purl !== null) {
    //if package has a purl, get vuln by purl
    query = {
      database: VulDatabase.SONATYPE,
      method: 'post',
      headers: {
        authKey: 'Authorization',
        authValue: 'Basic ' + AUTH,
      },
      params: { searchKey: '', searchValue: null },
      body: {
        coordinates: [pkg.purl],
      },
    };
  } else if (pkg.cpeName !== null) {
    //else if package has a cpe name, get vuln by cpe name
    query = {
      database: VulDatabase.NVD,
      method: 'get',
      headers: { authKey: 'apiKey', authValue: API_KEY },
      params: { searchKey: 'cpeName', searchValue: pkg.cpeName },
      body: null,
    };
  } else {
    //else use package name and version
    query = {
      database: VulDatabase.NVD,
      method: 'get',
      headers: { authKey: 'apiKey', authValue: API_KEY },
      params: {
        searchKey: 'keywordSearch',
        searchValue: `${pkg.name} v${pkg.version}`,
      },
      body: null,
    };
  }
  return query;
}

export { buildQuery };
