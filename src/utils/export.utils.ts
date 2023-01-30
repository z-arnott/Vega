import {PackageViewParam, severityRating, DisplayPackage, Vulnerability}  from './types.utils';
import { readPackagesDashboard } from "./storageFacade.utils";
/****************** EXPORT API **********************/
 export async function exportResults(sessionId:number){
    let file = JSON.stringify(await readPackagesDashboard(sessionId, PackageViewParam.NUMBER_OF_VULNERABILITIES,['LOW','MEDIUM','HIGH','CRITICAL'],1, 5000000000));
    return file;
}