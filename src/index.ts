import { Package, SbomFormat } from '../src/utils/types.utils';
import { parse } from '../src/services/parserContext.services';
import {
  DashboardRequest,
  getView,
} from '../src/services/viewFormatter.services';

import { analyzeSystem } from '../src/services/riskAnalysis.services';
import { writePackage } from '../src/utils/storageFacade.utils';
import fileUpload from 'express-fileupload';

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
  for (let pkg of packages) {
    writePackage(pkg, sessionId);
  }
  console.log(packages);
  res.send('Upload: parsed ' + packages.length + ' packages');
  //add middleware calls here as needed
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
