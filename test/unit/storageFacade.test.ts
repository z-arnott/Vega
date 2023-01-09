//import { supabase } from @;
//import { Database };
import { ReadSpecificPackage,ReadAllPackage,ReadMultipleVulnerability,WritePackageRequest } from '@utils/storageFacade.utils'; 
import { DBPackage, DBResponse, DBVulnerability } from '@utils/types.utils';
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

let expectedResult1: DBResponse={
  count: null,
  data: expectedData1,
  error: null,
  status: 200,
  statusText: "OK"

} 

test('Test 1: Read Specific PackageInfo Given SessionID and PackageID', () => {
  return ReadSpecificPackage(234,1).then((data) => {
    expect(data).toStrictEqual(expectedResult1);
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
        cveid: 7485,
        packageid: 3,
        impact: null,
        likelihood: null,
        risk: null,
        description: "broken window"
      },
      {
      cveid: 4765,
      packageid: 3,
      impact: null,
      likelihood: null,
      risk: null,
      description: "flat tire"
      }
      
      
    ];

let expectedResult3: DBResponse ={
  count: null,
  data: expectedData3,
  error: null,
  status: 200,
  statusText: "OK"

} 

test('Test 3: Read Multiple Vulnerabilities Given PackageID no sorting', () => {
  return ReadMultipleVulnerability(3).then((data) => {
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
  //return WritePackageRequest(expectedData4).then((data) => {
   // expect(data).toStrictEqual(expectedResult4)
  // }
  WritePackageRequest(expectedData4);
  return ReadSpecificPackage(348,5).then((data) => {
  expect(data).toStrictEqual(expectedResult4);
  });
  //write delete function to delete insert
  //if (ReadSpecificPackage(348,5) == expectedResult4){ }
});