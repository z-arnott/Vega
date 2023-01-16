import { Package, Vulnerability } from '../utils/types.utils';
import {logger} from '@utils/logger.utils';

/*********** Vulnerabiltiy Analysis ************/
interface Cvss{
    AV: number,
    AC: number,
    Au: number,
    C: number,
    I: number,
    A: number
}
function cvss3to2(cvss3Str:string):string{
    let cvss2Str = "";
    let metrics = cvss3Str.split('/');
    for(let metric of metrics){
        const [key, value] = metric.split(':');
        if(key == 'AV'){
            switch(value){
                //convert
                case 'P':{
                    cvss2Str += key + ':' +'L';
                    break;
                }
                //no change from v2 to v3
                default: {
                        cvss2Str += key + ':' + value;
                }
            }
            cvss2Str += '/';
        }
        else if(key == 'PR'){
            switch(value){
                //convert
                case 'L':{
                    cvss2Str += 'Au' + ':' +'S';
                    break;
                }
                case 'H':{
                    cvss2Str += 'Au' + ':' + 'M';
                    break;
                }
                //no change from v2 to v3
                default: {
                    cvss2Str += 'Au' + ':' + value;
                }
            }
            cvss2Str += '/';
        }
        else if(key == 'AC'){
            //no change from v2 to v3
            cvss2Str += key + ':' + value;
            cvss2Str += '/';
        }
        else if(key == 'AC'){
            //no change from v2 to v3
            cvss2Str += key + ':' + value;
            cvss2Str += '/';
        }
        else if(key == 'C' || key == 'I' || key == 'A'){
            //no change from v2 to v3
            cvss2Str += key + ':' + value;
            cvss2Str += '/';
        }
    }
    return cvss2Str;
}

function decodeCvssVector(cvssStr:string): Cvss{
    let cvss: Cvss = {AV: 0, AC: 0, Au: 0, C: 0, I: 0, A: 0};
    let metrics = cvssStr.split('/');
    for(let metric of metrics){
        const [key, value] = metric.split(':');
        if(key == 'AV'){
            switch(value){
                case 'L':{
                    cvss.AV = 0.4;
                    break;
                }
                case 'A': {
                    cvss.AV = 0.6;
                    break;
                }
                case 'N':{
                    cvss.AV = 1;
                    break;
                }
            }
        }
        else if(key == 'AC'){
            switch(value){
                case 'L':{
                    cvss.AC = 1;
                    break;
                }
                case 'M': {
                    cvss.AC = 0.75;
                    break;
                }
                case 'H':{
                    cvss.AC = 0.5;
                    break;
                }
            }
        }
        else if(key == 'Au'){
            switch(value){
                case 'M':{
                    cvss.Au = 0.5;
                    break;
                }
                case 'S': {
                    cvss.Au = 0.6;
                    break;
                }
                case 'N':{
                    cvss.Au = 1;
                    break;
                }
            }
        }
        else if(key == 'C'){
            switch(value){
                case 'C':{
                    cvss.C = 1;
                    break;
                }
                case 'P': {
                    cvss.C = 0.5;
                    break;
                }
                case 'N':{
                    cvss.C = 0;
                    break;
                }
            }
        }
        else if(key == 'I'){
            switch(value){
                case 'C':{
                    cvss.I = 1;
                    break;
                }
                case 'P': {
                    cvss.I = 0.5;
                    break;
                }
                case 'N':{
                    cvss.I = 0;
                    break;
                }
            }
        }
        else if(key == 'A'){
            switch(value){
                case 'C':{
                    cvss.A = 1;
                    break;
                }
                case 'P': {
                    cvss.A = 0.5;
                    break;
                }
                case 'N':{
                    cvss.A = 0;
                    break;
                }
            }
        }
        
    }
    return cvss;
}
function cveImpact(cvssStr:string){
    let cvss = decodeCvssVector(cvssStr);
    let impactConf = cvss.C * 100;
    let impactInt = cvss.I * 100;
    let impactAvail = cvss.A * 100;
    return (impactConf + impactInt + impactAvail)/3;
}

function cveLikelihood(cvssStr:string){
    let cvss = decodeCvssVector(cvssStr);
    return (cvss.AV * cvss.AC * cvss.Au);
}

function cveRisk(impact: number, likelihood: number){
    return (impact * likelihood);
}

function analyzeVulnerability(v: Vulnerability){
    v.impact = cveImpact(v.cvss2);
    v.likelihood = cveLikelihood(v.cvss2);
    v.risk = cveRisk(v.impact, v.likelihood);
}

/********** Pacakge Highest Risk ************/
function highestRisk(cves: Vulnerability[]) : number{
    let highest = 0;
    for(let v of cves){
        highest = Math.max(highest, v.risk);
    }
    return highest;
}
/******* Pacakge Consolidated Risk *********/
//One element in a sample set
interface SampleElement {
    exploited: Vulnerability[],
    notExploited: Vulnerability[]
}

//Compute the impact of one element in a sample set
//Impact(e) =min(Impactmax , SUMi_∈_ES(Impacti)) 
function impactElement(e: SampleElement): number{
    let sumImpacts = 0;
    for(let i =0; i<e.exploited.length; i++){
        sumImpacts += e.exploited[i].impact;
    }
    return Math.min(100, sumImpacts);
}

//Compute the likelihood of one element in a sample set
//Likelihood(e) = PRODUCTi_∈_ES((likelihoodi *j  PRODUCTi_∈_NES(1-likelihoodj))
function likelihoodElement(e: SampleElement) : number{
    let likelihood = 1
    for(let i =0; i < e.exploited.length; i++){
        let notExploitedLikelihood = 1;
        for(let j =0; j<e.notExploited.length; j++){
            notExploitedLikelihood *= (1 - e.notExploited[j].likelihood);
        }
        likelihood *= (e.exploited[i].likelihood * notExploitedLikelihood);
    }
    return likelihood;
}

//Create a sample space for a vulnerability list. 
//The sample space is defined as the set of all possible outcomes,
//where each vulnerability can be exploited OR notExploited 
function contstructSampleSpace(cves: Vulnerability[]) : SampleElement[]{
    let sampleSpace: SampleElement[] = [];
    let sampleSpaceSize = Math.pow(2, cves.length);
    
    //Construct each element in sample space
    for(let i = 0; i<sampleSpaceSize; i++){
        let element: SampleElement = {
            exploited: [],
            notExploited: []
        };
        //use binary representation; 1 = exploited, 0 = notExploted
        //B0 corresponds to cves[0], B1 corresponds to cves[1], ... BN corresponds to cves[N]
        let binaryStr = i.toString(2).padStart(cves.length, '0');
        
        //Assign each vulnerability to notExploited or Exploited
        for(let c = 0; c < binaryStr.length; c++){
            if(binaryStr.charAt(c) == '1'){
                element.exploited.push(cves[c])
            }else{
                element.notExploited.push(cves[c])
            }
        }

        sampleSpace.push(element);
    }
    return sampleSpace;
}

function consolidatedRisk(cves: Vulnerability[]):number{
    let sampleSpace: SampleElement[] = contstructSampleSpace(cves);
    let consolidatedRisk = 0;
    for(let e of sampleSpace){
        let likelihood = likelihoodElement(e);
        let impact = impactElement(e);
        consolidatedRisk  += (impact * likelihood);
    }
    return consolidatedRisk;
}

/********** System Risk ************/
function systemRisk(packages: Package[]) : number{
    let highest = 0;
    for(let p of packages){
        if(p.highestRisk == undefined){logger.warn("System Risk Analysis: " + p.id + " risk undefined");}
        else{
            highest = Math.max(highest, p.highestRisk);
        }
    }
    return highest;
}
export {systemRisk, consolidatedRisk, highestRisk, analyzeVulnerability, cvss3to2};