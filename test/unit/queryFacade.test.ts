import {Query, VulDatabase} from '@utils/types.utils';
import {getVulnerabilities} from '@utils/queryFacade.utils';
import {nvdCleaner} from '@utils/queryFacade.utils';
import {sonatypeCleaner} from '@utils/queryFacade.utils';

jest.setTimeout(20000)

//Create NVD query
let query1: Query =  {
    database: VulDatabase.NVD,
    method: 'get',
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    headers: {authKey: 'apiKey', authValue:'41bc2206-c2b2-4727-ae28-fbebdd66488a'},
    params: {searchKey: 'cveId', searchValue: 'CVE-2021-20089'},
    body: null
};

let expectedQ1 = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-20089",
                "sourceIdentifier": "vulnreport@tenable.com",
                "published": "2021-04-23T19:15:11.140",
                "lastModified": "2021-05-04T13:29:15.730",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') in purl 2.3.2 allows a malicious user to inject properties into Object.prototype."
                    },
                    {
                        "lang": "es",
                        "value": "Una Modificación Controlada Inapropiadamente de Object Prototype Attributes (\"Prototype Pollution\") en purl versión 2.3.2, permite a un usuario malicioso inyectar propiedades en Object.prototype"
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:S/C:P/I:P/A:P",
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "SINGLE",
                                "confidentialityImpact": "PARTIAL",
                                "integrityImpact": "PARTIAL",
                                "availabilityImpact": "PARTIAL",
                                "baseScore": 6.5,
                                "baseSeverity": "MEDIUM"
                            },
                            "exploitabilityScore": 8.0,
                            "impactScore": 6.4,
                            "acInsufInfo": false,
                            "obtainAllPrivilege": false,
                            "obtainUserPrivilege": false,
                            "obtainOtherPrivilege": false,
                            "userInteractionRequired": false
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "NVD-CWE-Other"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:purl_project:purl:2.3.2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F5B4D552-EE91-4EBC-BC2F-59FFC452BCAF"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/BlackFan/client-side-prototype-pollution/blob/master/pp/purl.md",
                        "source": "vulnreport@tenable.com",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        }
    ]
};

//Create NVD query
let query2: Query =  {
    database: VulDatabase.NVD,
    method: 'get',
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    headers: {authKey: 'apiKey', authValue: '41bc2206-c2b2-4727-ae28-fbebdd66488a'},
    params: {searchKey: 'cpeName', searchValue: 'cpe:2.3:a:1e:client:4.1.0.267:*:*:*:*:windows:*:*'},
    body: null
};

let expectedQ2 =
{
    "resultsPerPage": 2,
    "startIndex": 0,
    "totalResults": 2,
    "format": "NVD_CVE",
    "version": "2.0",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2020-16268",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2020-12-29T21:15:13.087",
                "lastModified": "2021-07-21T11:39:23.747",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "The MSI installer in 1E Client 4.1.0.267 and 5.0.0.745 allows remote authenticated users and local users to gain elevated privileges via the repair option. This applies to installations that have a TRANSFORM (MST) with the option to disable the installation of the Nomad module. An attacker may craft a .reg file in a specific location that will be able to write to any registry key as an elevated user."
                    },
                    {
                        "lang": "es",
                        "value": "El instalador MSI en 1E Client versiones 4.1.0.267 y 5.0.0.745, permite a los usuarios autenticados remotos y a los usuarios locales obtener privilegios elevados por medio de la opción de reparación.&#xa0;Esto se aplica a instalaciones que tienen un TRANSFORM (MST) con la opción de deshabilitar la instalación del módulo Nomad.&#xa0;Un atacante puede crear un archivo .reg en una ubicación específica que podrá escribir en cualquier clave de registro como un usuario elevado"
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 5.9
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:S/C:P/I:P/A:P",
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "SINGLE",
                                "confidentialityImpact": "PARTIAL",
                                "integrityImpact": "PARTIAL",
                                "availabilityImpact": "PARTIAL",
                                "baseScore": 6.5,
                                "baseSeverity": "MEDIUM"
                            },
                            "exploitabilityScore": 8.0,
                            "impactScore": 6.4,
                            "acInsufInfo": false,
                            "obtainAllPrivilege": false,
                            "obtainUserPrivilege": false,
                            "obtainOtherPrivilege": false,
                            "userInteractionRequired": false
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-668"
                            },
                            {
                                "lang": "en",
                                "value": "CWE-74"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:1e:client:4.1.0.267:*:*:*:*:windows:*:*",
                                        "matchCriteriaId": "E15F224E-1F50-483D-AAA0-F9D022C2B025"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:1e:client:5.0.0.745:*:*:*:*:windows:*:*",
                                        "matchCriteriaId": "ECFC24D6-F42F-481A-984D-EC4E7507E2BF"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://help.1e.com/display/GI/1E+Security+Advisory-1E+Client+for+Windows%3A+CVE-2020-16268%2C+CVE-2020-27643%2C+CVE-2020-27644%2C+CVE-2020-27645",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2020-27643",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2020-12-29T21:15:13.163",
                "lastModified": "2021-07-21T11:39:23.747",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "The %PROGRAMDATA%\\1E\\Client directory in 1E Client 5.0.0.745 and 4.1.0.267 allows remote authenticated users and local users to create and modify files in protected directories (where they would not normally have access to create or modify files) via the creation of a junction point to a system directory. This leads to partial privilege escalation."
                    },
                    {
                        "lang": "es",
                        "value": "El directorio %PROGRAMDATA%\\1E\\Client en 1E Client versiones 5.0.0.745 y 4.1.0.267, permite a los usuarios autenticados remotos y a los usuarios locales crear y modificar archivos en directorios protegidos (donde normalmente no tendrían acceso para crear o modificar archivos) mediante la creación de un punto de unión en un directorio del sistema.&#xa0;Esto conduce a una escalada parcial de privilegios"
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "NONE",
                                "baseScore": 6.5,
                                "baseSeverity": "MEDIUM"
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 3.6
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:S/C:N/I:P/A:N",
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "SINGLE",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "PARTIAL",
                                "availabilityImpact": "NONE",
                                "baseScore": 4.0,
                                "baseSeverity": "MEDIUM"
                            },
                            "exploitabilityScore": 8.0,
                            "impactScore": 2.9,
                            "acInsufInfo": false,
                            "obtainAllPrivilege": false,
                            "obtainUserPrivilege": false,
                            "obtainOtherPrivilege": false,
                            "userInteractionRequired": false
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-59"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:1e:client:4.1.0.267:*:*:*:*:windows:*:*",
                                        "matchCriteriaId": "E15F224E-1F50-483D-AAA0-F9D022C2B025"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:1e:client:5.0.0.745:*:*:*:*:windows:*:*",
                                        "matchCriteriaId": "ECFC24D6-F42F-481A-984D-EC4E7507E2BF"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://help.1e.com/display/GI/1E+Security+Advisory-1E+Client+for+Windows%3A+CVE-2020-16268%2C+CVE-2020-27643%2C+CVE-2020-27644%2C+CVE-2020-27645",
                        "source": "cve@mitre.org",
                        "tags": [
                            "Vendor Advisory"
                        ]
                    }
                ]
            }
        }
    ]
};

//Create NVD query
let query3: Query =  {
    database: VulDatabase.SonaType,
    method: 'post',
    url: 'https://ossindex.sonatype.org/api/v3/authorized/component-report',
    headers: {authKey: 'Authorization', authValue: 'Basic em9lYXJub3R0QGNtYWlsLmNhcmxldG9uLmNhOjQ5N2M0OTZiNmI5OTQyOWMwNzE5NjllMGMzYWZmYTkxZTk5MDY1ZWQ='},
    params: {searchKey: "", searchValue: null},
    body: {
            "coordinates":[
                "pkg:maven/org.yaml/snakeyaml@1.30"
            ]
        }
};


/** Sanity tests*/
//Test search by cveID
test('requests data from NVD', () => {
    return getVulnerabilities(query1).then(data => {
        delete data.timestamp;  //compare all data except timestamp
        expect(data).toStrictEqual(expectedQ1);
    });
  });

//Test search by cpeName
test('requests data from NVD', () => {
    return getVulnerabilities(query2).then(data => {
        delete data.timestamp;  //compare all data except timestamp
        expect(data).toStrictEqual(expectedQ2);
    });
  });

//Test cleaning
test('clean response NVD results', () => {
    return getVulnerabilities(query2).then(data => {
        expect(nvdCleaner(data)[0].cveId).toBe("CVE-2020-16268");
    });
});

test('clean response Sonatype results from', () => {
    return getVulnerabilities(query3).then(data => {
        expect(sonatypeCleaner(data)).toStrictEqual([]);
    });
});

//Unit Testing: sendQuery is the public facing function of query Facade
