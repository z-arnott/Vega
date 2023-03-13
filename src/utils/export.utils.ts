import {PackageViewParam, severityRating, DisplayPackage, Vulnerability}  from './types.utils';
import { readPackagesDashboard,countVulnerabilities, countPackages } from "./storageFacade.utils";
import { numericLiteral } from '@babel/types';
/****************** EXPORT API **********************/
/**
 * Read all packages in a session
 * @param sessionid associated with one user
 * @returns json of packages and nested vulnerabilitiies assoicated with id
 */
export async function exportResults(sessionId:number){
   //calculate number of vulnerabilities
    let number = await countVulnerabilities(sessionId)* await countPackages(sessionId ); //to give extra padding whether page size denotes packages or vulnerabilities
    if (number <1){
        let number =1;
    }
    //number is passed as an optional parameter of PAGE_SIZE to stringify all packages and vulnerabilities at once
    let file = JSON.stringify(await readPackagesDashboard(sessionId, PackageViewParam.NUMBER_OF_VULNERABILITIES,['LOW','MEDIUM','HIGH','CRITICAL'],1, number));
    return file;

    //current version does not output any packages that do not have associated vulnerabilities
    //discuss whether that's okay or if packages with no vulnerabilities should still be identified
}