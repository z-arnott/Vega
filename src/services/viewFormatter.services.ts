/****************** PARSING STRATEGY INTERFACE **********************/

import {
  countHighSeverityCves,
  readPackagesDashboard,
  readVulnerabilitiesDashboard,
  countVulnerabilities,
  countPackages,
  countHighRiskCves,
} from '../utils/storageFacade.utils';
import {
  Vulnerability,
  DisplayPackage,
  PackageViewParam,
  VulnerabilityViewParam,
} from '../utils/types.utils';

enum ViewType {
  PACKAGE = 'component',
  VULNERABILITY = 'vulnerability',
}

interface DashboardView {
  type: ViewType;
  Components_Detected: number;
  High_Severity_Vulnerabilities: number;
  High_Risk_Vulnerabilities: number;
  data: Vulnerability[] | DisplayPackage[];
}

export interface DashboardRequest {
  viewType: ViewType;
  sessionId: number;
  filter: {
    param: string;
    lower: number;
    upper: number;
  };
  page: number;
  sortParam: string;
}

export async function getView(req: DashboardRequest) {
  let viewFormatter: JsonFormatter;
  if (req.viewType == ViewType.PACKAGE) {
    viewFormatter = packageViewFormatter;
  } else {
    viewFormatter = vulnerabilityViewForamtter;
  }
  return viewFormatter(req);
}

/**
 *
 *
 * @interface JsonFormatter
 */
interface JsonFormatter {
  (req: DashboardRequest): Promise<DashboardView>;
}

function decodePackageViewParam(s: string): PackageViewParam {
  if (s == PackageViewParam.COMPONENT_REF) {
    return PackageViewParam.COMPONENT_REF;
  } else if (s == PackageViewParam.CONSOLIDATED_RISK) {
    return PackageViewParam.CONSOLIDATED_RISK;
  } else if (s == PackageViewParam.HIGHEST_RISK) {
    return PackageViewParam.HIGHEST_RISK;
  } else if (s == PackageViewParam.NAME) {
    return PackageViewParam.NAME;
  } else {
    //default
    return PackageViewParam.HIGHEST_RISK;
  }
}

function decodeVulnerabilityViewParam(s: string): VulnerabilityViewParam {
  if (s == VulnerabilityViewParam.CVEID) {
    return VulnerabilityViewParam.CVEID;
  } else if (s == VulnerabilityViewParam.SEVERITY) {
    return VulnerabilityViewParam.SEVERITY;
  } else if (s == VulnerabilityViewParam.RISK) {
    return VulnerabilityViewParam.RISK;
  } else if (s == VulnerabilityViewParam.IMPACT) {
    return VulnerabilityViewParam.IMPACT;
  } else if (s == VulnerabilityViewParam.LIKELIHOOD) {
    return VulnerabilityViewParam.LIKELIHOOD;
  } else {
    //default
    return VulnerabilityViewParam.SEVERITY;
  }
}

//Formatter Instances
let vulnerabilityViewForamtter: JsonFormatter;
let packageViewFormatter: JsonFormatter;

packageViewFormatter = async function (
  req: DashboardRequest
): Promise<DashboardView> {
  return {
    type: ViewType.PACKAGE,
    Components_Detected: await countPackages(req.sessionId),
    High_Risk_Vulnerabilities: await countHighRiskCves(req.sessionId),
    High_Severity_Vulnerabilities: await countHighSeverityCves(req.sessionId),
    data: await readPackagesDashboard(
      req.sessionId,
      decodePackageViewParam(req.sortParam),
      decodePackageViewParam(req.filter.param),
      req.filter.lower,
      req.filter.upper,
      req.page
    ),
  };
};

vulnerabilityViewForamtter = async function (
  req: DashboardRequest
): Promise<DashboardView> {
  return {
    type: ViewType.VULNERABILITY,
    Components_Detected: await countPackages(req.sessionId),
    High_Risk_Vulnerabilities: await countHighRiskCves(req.sessionId),
    High_Severity_Vulnerabilities: await countHighSeverityCves(req.sessionId),
    data: await readVulnerabilitiesDashboard(
      req.sessionId,
      decodeVulnerabilityViewParam(req.sortParam),
      decodeVulnerabilityViewParam(req.filter.param),
      req.filter.lower,
      req.filter.upper,
      req.page
    ),
  };
};

/* Register view fromatters here */
let viewFormatters = {
  [ViewType.PACKAGE]: packageViewFormatter,
  [ViewType.VULNERABILITY]: vulnerabilityViewForamtter,
};
