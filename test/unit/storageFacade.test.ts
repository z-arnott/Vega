//import { supabase } from @;
//import { Database };

import { ReadSpecificPackage,ReadAllPackage,ReadMultipleVulnerability,WritePackageRequest, DeletePackage, WriteVulnRequest, DeleteVuln } from '@utils/storageFacade.utils'; 
import { DBPackage, DBResponse, DBVulnerability, DBVulnerabilityInput } from '@utils/types.utils';
import {expect, jest, test} from '@jest/globals';
import dotenv from 'dotenv';

//Setup
dotenv.config();
const supabaseUrl = process.env.SUPABASE_URL as string;
const supabaseKey = process.env.SUPABASE_KEY as string;
jest.setTimeout(20000);

//Test 1: Can Read Specific Package
//Error: these let statements wont work so I'm manually inputting the values in the test function
let sessionid: 234;
let packageid: 1;

let expectedData1: DBPackage[] = [
    {
        packageid: 1,
        sessionid: 234,
        name: "firstname",
        packageversion: null,
        consrisk: 3.5, 
        impact: 2.3,
        likelihood: 2.3,
        highestrisk: 2.4,
        purl: "hellopurl",
        cpename: "hellocpename"
      }
    ];

// let expectedResult1: DBResponse={
//   count: null,
//   data: expectedData1,
//   error: null,
//   status: 200,
//   statusText: "OK"

// } 

test('Test 1: Read Specific PackageInfo Given SessionID and PackageID', () => {
  return ReadSpecificPackage(234,1).then((data) => {
    expect(data).toStrictEqual(expectedData1);
  });
});

//Test 2: Can Read All Package

let expectedData2: DBPackage[] = [
    {
        packageid: 1,
        sessionid: 234,
        name: "firstname",
        packageversion: null,
        consrisk: 3.5, 
        impact: 2.3,
        likelihood: 2.3,
        highestrisk: 2.4,
        purl: "hellopurl",
        cpename: "hellocpename"
      },
      {
        packageid: 4,
        sessionid: 234,
        name: "fourthname",
        packageversion: "3.5.4",
        consrisk: 8.6, 
        impact: 1.3,
        likelihood: 9.4,
        highestrisk: 9.8,
        purl: "olehello",
        cpename: "rerunshere"
      }
    ];

let expectedResult2: DBResponse={
  count: null,
  data: expectedData2,
  error: null,
  status: 200,
  statusText: "OK"

} 

test('Test 2: Read All PackageInfo Given SessionID', () => {
  return ReadAllPackage(234).then((data) => {
    expect(data).toStrictEqual(expectedResult2);
  });
});

//Test 3: Read Multiple Vulnerabilities Given PackageID


let expectedData3: DBVulnerability[] = [
    {
      packageid:1,
      vulnerabilities:{
        cveid: 7485,
        impact: null,
        likelihood: null,
        risk: null,
        description: "broken window"
        }
      },
      {
      packageid: 1,
      vulnerabilities:{
        cveid: 4765,
        impact: null,
        likelihood: null,
        risk: null,
        description: "flat tire"
        }
    }];


test('Test 3: Read Multiple Vulnerabilities Given PackageID no sorting', () => {
  return ReadMultipleVulnerability(1).then((data) => {
    //expect(data).toEqual(expect.arrayContaining(expectedData3));
    expect(data).toEqual(expect.arrayContaining(expectedData3)); //good to use here instead of .toEqual or .toStrictEqual 
  });
});

//Test 4: Write One package

let expectedData4: DBPackage[] = [{
  packageid: 5,
  sessionid: 348,
  name: "randomtest5",
  packageversion: null,
  consrisk: 7.4,
  impact: 9.0,
  likelihood: 7.6,
  highestrisk: 9.4,
  purl: null,
  cpename: null
}
]

let expectedResult4: DBResponse ={
  count: null,
  data: expectedData4,
  error: null,
  status: 200,
  statusText: "OK"
}

test('Test 4: Write One Package', () => {
  //WritePackageRequest(expectedData4);
  return WritePackageRequest(expectedData4).then((status) => {
  expect(status).toStrictEqual(201); //201 code for content created
  });
}); 

//Test 5: Delete One Package Given Packageid
test('Test 5: Delete One Package', () =>{
  return DeletePackage(5).then((status) => {
    expect(status).toStrictEqual(204); //204 code for success, no content to return
  });
});

//Test 6: Write Packages in Bulk
let expectedData6: DBPackage[] = [{
  packageid: 5,
  sessionid: 348,
  name: "randomtest5",
  packageversion: null,
  consrisk: 7.4,
  impact: 9.0,
  likelihood: 7.6,
  highestrisk: 9.4,
  purl: null,
  cpename: null
},
{
  packageid: 6,
  sessionid: 348,
  name: "randomtest6",
  packageversion: null,
  consrisk: 7.4,
  impact: 9.0,
  likelihood: 7.6,
  highestrisk: 9.4,
  purl: null,
  cpename: null
}
]

test('Test 6: Write Packages in Bulk', () => {
  //WritePackageRequest(expectedData4);
  return WritePackageRequest(expectedData6).then((status) => {
  expect(status).toStrictEqual(201); //201 code for content created
  });
}); 

test('Test 7: Delete Multiple Packages', () =>{
  DeletePackage(5);
  DeletePackage(6);
  return ReadSpecificPackage(null,6).then((data) => {
    expect(data).toStrictEqual(null); //querying a non-existant entry yield a null in the data field
  });
});

//Test 8: Write One Vulnerabilities
let expectedData8: DBVulnerabilityInput = {
  cveid: 5,
  impact: 9.0,
  likelihood: 7.6,
  risk:7.3,
  description: "painful twist"
}

test('Test 8: Write One Vulnerability', () => {
  return WriteVulnRequest(expectedData8).then((status) => {
  expect(status).toStrictEqual(201); //201 code for content created
  });
}); 


//Test 9: Delete One Vulnerability
test('Test 9: Delete Single Vulnerability', () =>{
  return DeleteVuln(5).then((status) => {
    expect(status).toStrictEqual(204); //querying a non-existant entry yield a null in the data field
  });
});

//Test 9: Write Multiple Vulnerabilities
let expectedData9: DBVulnerabilityInput[] = [
  {
      cveid: 5253,
      impact: null,
      likelihood: null,
      risk: null,
      description: "painful twist"
    },
    {
    cveid: 508,
    impact: null,
    likelihood: null,
    risk: null,
    description: "torn guitar strig"
    }
  ]
  
  test('Test 10: Write Multiple Vulnerabilities',() =>{
  return WriteVulnRequest(expectedData9).then((status) => {
  expect(status).toStrictEqual(201);
  });
});

//Delete dummy vulnerabilities created in last step
test('Test 11: Delete Multiple Vulnerabilities', () =>{
  DeleteVuln(5253);
  return DeleteVuln(508).then((status) => {
    expect(status).toStrictEqual(204); //querying a non-existant entry yield a null in the data field
  });
});
  

