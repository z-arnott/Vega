import {
  Package,
  Query,
  Vulnerability,
  VulDatabase,
} from '../src/utils/types.utils';
import { sendQuery } from '../src/utils/queryFacade.utils';
import { parse } from '../src/services/parserContext.services';
import { buildQuery } from '../src/services/queryVulnerabilities.services';
import {
  DashboardRequest,
  getView,
} from '../src/services/viewFormatter.services';

import { analyzeSystem } from '../src/services/riskAnalysis.services';
import {
  readAllPackages,
  writePackage,
  writeVuln,
  bulkInsertVuln,
} from '../src/utils/storageFacade.utils';
import { bulkCreatePackage } from '../src/utils/storageFacade.utils';
import fileUpload from 'express-fileupload';

import dotenv from 'dotenv';
import workerpool from 'workerpool';

dotenv.config();
const API_KEY = process.env.API_KEY as string;
const AUTH = process.env.AUTHORIZATION as string;

const express = require('express');
const app = express();
var cors = require('cors');
app.use(cors());
app.use(express.json());
app.use(fileUpload());
const port = 8088; // default port to listen

//Homepage
//define a route handler for the default home page
app.get('/', (req: any, res: any) => {
  res.send('Hello world!');
});

/*************** Add supported endpoints here ***************/

// define a route handler for the Upload endpoint
app.post('/upload', (req: any, res: any, next: any) => {
  let sbom = req.files.sbom.data.toString('utf8');
  let sbomType = req.query.format;
  let sessionId = req.query.sessionId;
  let packages = parse(sbom, sbomType);
  bulkCreatePackage(packages, sessionId);
  console.log(packages);
  res.send('Upload: parsed ' + packages.length + ' packages');
  //add middleware calls here as needed
});

app.get('/query', async (req: any, res: any, next: any) => {
  const sessionId = req.query.sessionId;
  const pkgnum = req.query.pkgnum;
  const packages: Package[] = await readAllPackages(sessionId);
  console.log('PACKAGES:', packages[0]);

  //** PULL ONLY THE SPECIFIED PACKAGE NUMBER */
  // let query: Query = buildQuery(packages[pkgnum]);
  // console.log(query);
  // sendQuery(query)
  //   .then((data) => {
  //     res.send(data);
  //   })
  //   .catch((err) => {
  //     console.log('error: ', err);
  //     res.send(err);
  //   });

  //** MANUALLY ITERATE VULNERABILITIES */
  const pool = workerpool.pool();
  let vulnDict: any = {};
  async function firstTenPackages(vulnDict: any) {
    let count:number = 0;
    for (let i = 0; i < packages.length; i++) {
      let query: Query = buildQuery(packages[i]);
      console.log('QUERY:', query);
      let vulns: Vulnerability[] = [];
      try {
        vulns = await sendQuery(query);
        vulnDict[query.params.searchValue ? query.params.searchValue : 'purlSearch_'+i] =
          vulns;
        count += vulns.length;
        console.log('vulnerabilities detected:', count, vulnDict);
      } catch (err) {
        console.log('error: ', err);
      }
      if(vulns.length > 0){
        try {
          vulns.forEach((vuln: Vulnerability) => {
            vuln.packageRef=packages[i].ref;
          });
          let status = bulkInsertVuln(packages[i], vulns, sessionId);
          console.log('added to db status:', vulns, status);
        } catch (err) {
          console.log('error: ', err);
        }
      }
    }
    return vulnDict;
  }
  const d = await firstTenPackages(vulnDict);
  console.log('unified vuln db', d);
  res.send(d);

  //** ITERATE THROUHG ALL THE PACKAGES */
  // let vulnDict: any = {};
  // await packages.every(async (pkg: Package) => {
  //   let query: Query = buildQuery(pkg);
  //   sendQuery(query)
  //     .then((data) => {
  //       console.log('no error: ', data);
  //       if (pkg.cpeName) {
  //         if (typeof data[0] === 'string') {
  //           console.log('data returned is a string');
  //           vulnDict[pkg.cpeName] = data[0];
  //           return false;
  //         } else {
  //           vulnDict[pkg.cpeName] = data;
  //         }
  //       }
  //       // res.send(data);
  //       return true;
  //     })
  //     .catch((err) => {
  //       console.log('error: ', err);
  //       console.log(vulnDict);
  //       return false;
  //     });
  // });
  // res.send(vulnDict);

  // vulnerabilities.forEach(async (vuln: Vulnerability) => {
  //   await writeVuln(vuln, sessionId);
  // });
  // });
});

app.get('/riskanalysis', (req: any, res: any, next: any) => {
  let sessionId = req.query.sessionId;
  analyzeSystem(sessionId).then( () => {
    res.send('Analysis complete');
  });
});

app.get('/dashboard', (req: any, res: any, next: any) => {
  let riskFilters = req.query.riskFilters;
  let severityFilters = req.query.severityFilters;
  if (!riskFilters) {
    riskFilters = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  }
  if (!severityFilters) {
    severityFilters = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  }
  let reqParams: DashboardRequest = {
    page: +req.query.page,
    sortParam: req.query.sortBy,
    viewType: req.query.view,
    sessionId: +req.query.sessionId,
    riskFilters: riskFilters,
    severityFilters: severityFilters,
  };
  getView(reqParams).then((results) => {
    res.send(results);
  });
});
/*************** Start Server ***************/
// start the Express server
app.listen(port, () => {
  console.log(`server started at http://localhost:${port}`);
});

/*************** Exit Server ***************/
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  app.close(() => {
    console.log('HTTP server closed');
  });
});
