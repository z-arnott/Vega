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
import { purge_session, writePackage } from '../src/utils/storageFacade.utils';
import { bulkCreatePackage } from '../src/utils/storageFacade.utils';
import {
  readAllPackages,
  insertVuln,
} from '../src/utils/storageFacade.utils';
import fileUpload from 'express-fileupload';
import { exportResults } from '../src/utils/export.utils';


import dotenv from 'dotenv';

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
  console.log("upload:"+sessionId);
  bulkCreatePackage(packages, sessionId).then( () => {
    console.log(packages);
    res.send('Upload: parsed ' + packages.length + ' packages');
  });
  //add middleware calls here as needed
});

app.get('/query', async (req: any, res: any, next: any) => {
  const sessionId = req.query.sessionId;
  console.log("query"+sessionId);
  const packages: Package[] = await readAllPackages(sessionId);
  console.log('PACKAGES:', packages, '\n');
  let vulns: Vulnerability[] = [];
  let j = packages.length;
  let timeout = 500;

  for (let i = 0; i < packages.length; i++) {
    let query: Query = buildQuery(packages[i]);

    sendQuery(query)
      .then((data: Vulnerability[]) => {
        console.log('DATA RETURNED BY QUERY: ', data);
        vulns.concat(data);
        let k = data.length;
        data.forEach((vuln: Vulnerability) => {
          vuln['packageRef'] = packages[i]['ref'];
          insertVuln(vuln, sessionId)
            .then((status) => {
              console.log('added to db status:', vuln, status)
              k--;
              if(k == 0){
                j--;
              }
            })
            .catch((err) => {
              console.log('ERROR: ', vuln, err)
            });
        });
        if(data.length == 0){j--;}
      })
      .catch((err) => {
        console.log('error in sendQuery: ', err);
        // res.send(err);
        j--;
      });
  }
  while(j > 0 && timeout >0){
    await new Promise(r => setTimeout(r, 200));
    timeout--;
    console.log(timeout, j);
  }
  return res.send(vulns);
});

app.get('/riskanalysis', (req: any, res: any, next: any) => {
  let sessionId = req.query.sessionId;
  console.log("risk analysis"+sessionId);
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
  console.log(reqParams.sessionId);
  getView(reqParams).then((results) => {
    res.send(results);
  });
});

app.get('/purge', (req: any, res: any, next: any) => {
  let sessionId = req.query.sessionId;
  purge_session(sessionId);
  res.send('purged');
});
//export
app.get('/export',(req: any, res: any, next: any) => {
  let sessionId = req.query.sessionId;
  exportResults(sessionId).then((file) =>{
    res.send(file);
  })
 } );
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