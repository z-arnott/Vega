const express = require('express');
const app = express();
const port = 8081; // default port to listen

//Homepage
//define a route handler for the default home page
app.get('/', (req: any, res: any) => {
  res.send('Hello world!');
});

/*************** Add supported endpoints here ***************/

// define a route handler for the Upload endpoint
app.get(
  '/upload',
  (req: any, res: any, next: any) => {
    res.send('Upload: Hello world!');
    //add middleware calls here as needed
  },
  //Define middleware
  (req: any, res: any, next: any) => {
    console.log("Upload's middleware called!");
  }
);

/*************** Start Server ***************/
// start the Express server
app.listen(port, () => {
  console.log(`server started at http://localhost:${port}`);
});
