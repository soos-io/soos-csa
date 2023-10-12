import FormData from "form-data";
import { isNil } from "../utils/Utilities";
import createHttpClient, {
  ICodedMessageModel,
  IHttpRequestParameters,
  isAxiosError,
} from "./api-client";

export interface IContributingDeveloperAudit {
  source: string | null;
  sourceName: string | null;
  contributingDeveloperId: string | null;
}

interface ICreateAnalysisScanStructureArguments extends IHttpRequestParameters {
  clientId: string;
  projectName: string;
  commitHash: string | null;
  branch: string | null;
  buildVersion: string | null;
  buildUri: string | null;
  branchUri: string | null;
  integrationType: string;
  operatingEnvironment: string;
  integrationName: string;
  appVersion: string;
}

export enum ScanType {
  SCA = "Sca",
  DAST = "Dast",
  CSA = "Csa",
}

interface ICreateScanArguments extends ICreateAnalysisScanStructureArguments {
  scanType: ScanType;
}

interface IApiCreateScanRequestBody {
  projectName: string;
  commitHash: string | null;
  branch: string | null;
  buildVersion: string | null;
  buildUri: string | null;
  branchUri: string | null;
  integrationType: string;
  operatingEnvironment: string;
  integrationName: string | null;
  contributingDeveloperAudit?: IContributingDeveloperAudit[];
}

interface IApiCreateScanResponseBody {
  clientHash: string;
  projectHash: string;
  branchHash: string;
  scanId: string | null;
  analysisId: string;
  scanType: string;
  scanUrl: string;
  scanStatusUrl: string;
  errors: ICodedMessageModel[] | null;
}

interface ICreateScanReturn {
  projectHash: string;
  branchHash: string;
  scanId: string;
  reportUrl: string;
  scanStatusUrl: string;
}

export async function createScan({
  baseUri,
  apiKey,
  clientId,
  projectName,
  commitHash,
  branch,
  buildVersion,
  buildUri,
  branchUri,
  integrationType,
  operatingEnvironment,
  integrationName,
  scanType,
}: ICreateScanArguments): Promise<ICreateScanReturn> {
  const client = createHttpClient({
    baseUri,
    apiKey,
    clientName: "Create Scan",
  });
  const body: IApiCreateScanRequestBody = {
    projectName: projectName,
    commitHash: commitHash,
    branch: branch,
    buildVersion: buildVersion,
    buildUri: buildUri,
    branchUri: branchUri,
    integrationType: integrationType,
    operatingEnvironment: operatingEnvironment,
    integrationName: integrationName,
  };

  const response = await client.post<IApiCreateScanResponseBody>(
    `clients/${clientId}/scan-types/${scanType}/scans`,
    body
  );

  return {
    projectHash: response.data.projectHash,
    branchHash: response.data.branchHash,
    scanId: response.data.scanId ?? response.data.analysisId,
    reportUrl: response.data.scanUrl,
    scanStatusUrl: response.data.scanStatusUrl,
  };
}

interface IUploadSBOMFilesArguments extends IHttpRequestParameters {
  clientId: string;
  projectHash: string;
  branchHash: string;
  analysisId: string;
  sbomFiles: FormData;
}

export enum PackageManagerType {
  Unknown = "Unknown",
  CFamily = "CFamily",
  Dart = "Dart",
  Erlang = "Erlang",
  Go = "Go",
  Homebrew = "Homebrew",
  Java = "Java",
  NPM = "NPM",
  NuGet = "NuGet",
  Php = "Php",
  Python = "Python",
  Ruby = "Ruby",
  Rust = "Rust",
  Swift = "Swift",
}

export enum ManifestStatus {
  Unknown = "Unknown",
  Valid = "Valid",
  OnlyDevDependencies = "OnlyDevDependencies",
  OnlyLockFiles = "OnlyLockFiles",
  OnlyNonLockFiles = "OnlyNonLockFiles",
  NoPackages = "NoPackages",
  UnknownManifestType = "UnknownManifestType",
  UnsupportedManifestVersion = "UnsupportedManifestVersion",
  ParsingError = "ParsingError",
  Empty = "Empty",
}

interface IUploadManifestResponseManifest {
  name: string;
  filename: string;
  packageManager: PackageManagerType;
  status: ManifestStatus;
  statusMessage: string;
}

interface IUploadManifestResponse {
  message: string;
  manifests?: Array<IUploadManifestResponseManifest> | undefined;
}

interface IUploadResponseError extends ICodedMessageModel {
  validManifestCount: number;
  invalidManifestCount: number;
  manifests: Array<{
    name: string;
    filename: string;
    packageManager: PackageManagerType;
    status: string;
    statusMessage: string;
  }>;
}

/**
 * @throws Error
 */
export async function uploadSBOMFiles({
  baseUri,
  apiKey,
  clientId,
  projectHash,
  analysisId,
  sbomFiles,
}: IUploadSBOMFilesArguments): Promise<IUploadManifestResponse> {
  const client = createHttpClient({
    baseUri,
    apiKey,
    clientName: "Upload  SBOM Files",
    errorResponseHandler: (rejectedResponse) => {
      if (isAxiosError<IUploadResponseError | undefined>(rejectedResponse)) {
        if (rejectedResponse.response?.data?.code === "NoManifestsAccepted") {
          logger.info(
            `SBOM Files: \n`,
            `  ${rejectedResponse.response.data.message} \n`,
            rejectedResponse.response.data.manifests
              ?.map((m) => `  ${m.name}: ${m.statusMessage}`)
              .join("\n")
          );
        }
      }
    },
  });

  try {
    const headers: FormData.Headers = await new Promise((resolve) =>
      sbomFiles.getLength((error, length) =>
        isNil(error) && !isNil(length)
          ? resolve(sbomFiles.getHeaders({ "Content-Length": length.toString() }))
          : resolve(sbomFiles.getHeaders())
      )
    );

    const response = await client.post<IUploadManifestResponse>(
      `clients/${clientId}/projects/${projectHash}/analysis/${analysisId}/manifests`,
      sbomFiles,
      {
        headers: headers,
      }
    );

    return response.data;
  } catch (e) {
    throw e;
  }
}

interface IStartAnalysisArguments extends IHttpRequestParameters {
  clientId: string;
  projectHash: string;
  analysisId: string;
}

/**
 * @throws Error
 */
export async function startAnalysisScan({
  baseUri,
  apiKey,
  clientId,
  projectHash,
  analysisId,
}: IStartAnalysisArguments): Promise<void> {
  const client = createHttpClient({ baseUri, apiKey, clientName: "Start Analysis Scan" });
  await client.put(`clients/${clientId}/projects/${projectHash}/analysis/${analysisId}`);
}

interface ICheckAnalysisScanStatusArguments extends IHttpRequestParameters {
  reportStatusUrl: string;
}

export enum ScanStatus {
  Unknown = "Unknown",
  Queued = "Queued",
  Manifest = "Manifest",
  LocatingDependencies = "LocatingDependencies",
  LoadingPackageDetails = "LoadingPackageDetails",
  LocatingVulnerabilities = "LocatingVulnerabilities",
  RunningGovernancePolicies = "RunningGovernancePolicies",
  Finished = "Finished",
  FailedWithIssues = "FailedWithIssues",
  Incomplete = "Incomplete",
  Error = "Error",
}

const CompletedScanStatuses = [
  ScanStatus.Error,
  ScanStatus.Incomplete,
  ScanStatus.FailedWithIssues,
  ScanStatus.Finished,
];

interface ICheckAnalysisScanStatusReturn {
  status: ScanStatus;
  violations: { count: number } | null;
  vulnerabilities: { count: number } | null;
  clientHash: string;
  projectHash: string;
  branchHash: string;
  scanId: string;
  analysisId: string;
  scanType: string;
  scanUrl: string;
  scanStatusUrl: string;
  errors: ICodedMessageModel[] | null;
}

export interface IAnalysisScanStatus extends Pick<ICheckAnalysisScanStatusReturn, "status"> {
  isComplete: boolean;
  isSuccess: boolean;
  hasIssues: boolean;
  violations: number;
  vulnerabilities: number;
  errors: ICodedMessageModel[];
}

/**
 * @throws Error
 */
export async function checkAnalysisScanStatus({
  baseUri,
  apiKey,
  reportStatusUrl,
}: ICheckAnalysisScanStatusArguments): Promise<IAnalysisScanStatus> {
  const client = createHttpClient({ baseUri, apiKey, clientName: "Check Analysis Scan Status" });
  const response = await client.get<ICheckAnalysisScanStatusReturn>(reportStatusUrl);
  const violationCount = response.data.violations?.count ?? 0;
  const vulnerabilityCount = response.data.vulnerabilities?.count ?? 0;
  return {
    status: response.data.status,
    isComplete: CompletedScanStatuses.includes(response.data.status),
    isSuccess: response.data.status === ScanStatus.Finished,
    hasIssues: violationCount > 0 || vulnerabilityCount > 0,
    violations: violationCount,
    vulnerabilities: vulnerabilityCount,
    errors: response.data.errors ?? [],
  };
}

export interface IUpdateScanStatusArguments extends IHttpRequestParameters {
  clientId: string;
  projectHash: string;
  branchHash: string;
  scanType: ScanType;
  scanId: string;
  status: ScanStatus;
  message: string;
}

/**
 * @throws Error
 */
export async function updateScanStatus({
  baseUri,
  apiKey,
  clientId,
  projectHash,
  branchHash,
  scanType,
  scanId,
  status,
  message,
}: IUpdateScanStatusArguments): Promise<void> {
  const client = createHttpClient({ baseUri, apiKey, clientName: "Update Scan Status" });
  await client.patch(
    `clients/${clientId}/projects/${projectHash}/branches/${branchHash}/scan-types/${scanType}/scans/${scanId}`,
    {
      status: status,
      message: message,
    }
  );
}
