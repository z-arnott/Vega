import { Package, SbomFormat } from '../src/utils/types.utils';
import {parse} from '../src/services/parserContext.services';
import fileUpload from 'express-fileupload';

const express = require('express');
const app = express();
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
app.post(
  '/upload',
  (req: any, res: any, next: any) => {
    let sbom = req.files.sbom.data.toString('utf8');
    let sbomType = req.query.format;
    let packages = parse(sbom, sbomType);
    console.log(packages);
    res.send('Upload: parsed ' + packages.length +' packages');
    //add middleware calls here as needed
  }
);

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
  })
})
