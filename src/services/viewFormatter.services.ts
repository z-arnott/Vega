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
  severityRating,
} from '../utils/types.utils';

enum ViewType {
  PACKAGE = 'Component',
  VULNERABILITY = 'Vulnerability',
}

interface DashboardView {
  type: ViewType;
  stats: {
    Components_Detected: number;
    Vulnerabilities_Identified: number;
    High_Severity_Vulnerabilities: number;
    High_Risk_Vulnerabilities: number;
  };
  data: Vulnerability[] | DisplayPackage[];
}

export interface DashboardRequest {
  viewType: ViewType;
  sessionId: number;
  riskFilters: string[];
  severityFilters: string[];
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
  if (s in PackageViewParam) {
    return PackageViewParam[s as keyof typeof PackageViewParam];
  } else {
    return PackageViewParam.HIGHEST_RISK;
  }
}

function decodeVulnerabilityViewParam(s: string): VulnerabilityViewParam {
  if (s in VulnerabilityViewParam) {
    return VulnerabilityViewParam[s as keyof typeof VulnerabilityViewParam];
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
    stats: {
      Components_Detected: await countPackages(req.sessionId),
      Vulnerabilities_Identified: await countVulnerabilities(req.sessionId),
      High_Risk_Vulnerabilities: await countHighRiskCves(req.sessionId),
      High_Severity_Vulnerabilities: await countHighSeverityCves(req.sessionId),
    },
    data: await readPackagesDashboard(
      req.sessionId,
      decodePackageViewParam(req.sortParam),
      req.riskFilters,
      req.page
    ),
  };
};

vulnerabilityViewForamtter = async function (
  req: DashboardRequest
): Promise<DashboardView> {
  return {
    type: ViewType.VULNERABILITY,
    stats: {
      Components_Detected: await countPackages(req.sessionId),
      Vulnerabilities_Identified: await countVulnerabilities(req.sessionId),
      High_Risk_Vulnerabilities: await countHighRiskCves(req.sessionId),
      High_Severity_Vulnerabilities: await countHighSeverityCves(req.sessionId),
    },
    data: await readVulnerabilitiesDashboard(
      req.sessionId,
      decodeVulnerabilityViewParam(req.sortParam),
      req.riskFilters,
      req.severityFilters,
      req.page
    ),
  };
};

/* Register view fromatters here */
let viewFormatters = {
  [ViewType.PACKAGE]: packageViewFormatter,
  [ViewType.VULNERABILITY]: vulnerabilityViewForamtter,
};
