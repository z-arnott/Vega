class NoVulnerabilitiesError extends Error {
  constructor(message: string, cause: string) {
    super('There were no vulnerabilities for this package');
  }
}

class ResponseUndefinedError extends Error {
  constructor(message: string, cause: string) {
    super('Response was undefined');
  }
}
