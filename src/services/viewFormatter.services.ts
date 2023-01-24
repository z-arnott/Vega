/****************** PARSING STRATEGY INTERFACE **********************/

import { Vulnerability, DisplayPackage } from '@utils/types.utils';

interface VulnerabilityView {
  Components_Detected: number;
  Vulnerabilities_Identified: number;
  High_Severity_Vulnerabilities: number;
  High_Risk_Vulnerabilities: number;
  Vulnerabilities: Vulnerability[]; // insert as many vulnerabilities as necessary
}

export interface PackageView {
  Components_Detected: number;
  Vulnerabilities_Identified: number;
  High_Severity_Vulnerabilities: number;
  High_Risk_Vulnerabilities: number;
  Components: DisplayPackage[]; // insert as many packages as necessary
}

interface DashboardView {
  type: string;
  data: PackageView | VulnerabilityView;
}

interface DashboardRequest {
  viewType: string;
  filterParam: string;
  page: number;
  sortParam: string;
}

/**
 *
 *
 * @interface JsonFormatter
 */
interface JsonFormatter {
  (req: DashboardRequest): DashboardView;
}

//Formatter Instances
let vulnerabilityViewForamtter: JsonFormatter;
let packageViewFormatter: JsonFormatter;
