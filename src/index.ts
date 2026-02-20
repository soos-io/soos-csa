import { version } from "../package.json";
import { exit } from "process";
import { spawn } from "child_process";
import { Readable } from "node:stream";
import FormData from "form-data";
import {
  FileUtilities,
  getAnalysisExitCodeWithMessage,
  isScanDone,
  obfuscateCommandLine,
  obfuscateProperties,
  reassembleCommandLine,
} from "@soos-io/api-client/dist/utilities";
import {
  ScanStatus,
  ScanType,
  soosLogger,
  IntegrationName,
  IntegrationType,
  AttributionFormatEnum,
  AttributionFileTypeEnum,
} from "@soos-io/api-client";
import AnalysisService from "@soos-io/api-client/dist/services/AnalysisService";
import { SOOS_CSA_CONSTANTS } from "./constants";
import AnalysisArgumentParser, {
  IBaseScanArguments,
} from "@soos-io/api-client/dist/services/AnalysisArgumentParser";

interface ICSAAnalysisArgs extends IBaseScanArguments {
  otherOptions: string;
  targetToScan: string;
}
const parseArgs = (): ICSAAnalysisArgs => {
  const analysisArgumentParser = AnalysisArgumentParser.create(
    IntegrationName.SoosCsa,
    IntegrationType.Script,
    ScanType.CSA,
    version,
  );

  analysisArgumentParser.addArgument("otherOptions", "Other Options to pass to syft.");

  analysisArgumentParser.addArgument(
    "targetToScan",
    "The target to scan. Should be a docker image name or a path to a directory containing a Dockerfile",
    { useNoOptionKey: true },
  );

  return analysisArgumentParser.parseArguments();
};

const runSyft = async (args: ICSAAnalysisArgs): Promise<void> => {
  return new Promise((resolve, reject) => {
    const syftArgs = [
      args.targetToScan,
      `-o syft-json=${SOOS_CSA_CONSTANTS.ResultsFilePath}`,
      args.otherOptions,
    ];
    soosLogger.info(`Running syft with args: ${syftArgs}`);
    const syftProcess = spawn("syft", syftArgs, {
      shell: true,
      stdio: "inherit",
    });

    syftProcess.on("close", (code) => {
      soosLogger.debug(`syft: child process exited with code ${code}`);
      if (code === 0) {
        resolve();
      } else {
        reject(`syft: child process exited with code ${code}`);
      }
    });
  });
};

const runAnalysis = async (args: ICSAAnalysisArgs): Promise<void> => {
  const scanType = ScanType.CSA;
  const soosAnalysisService = AnalysisService.create(args.apiKey, args.apiURL);

  let projectHash: string | undefined;
  let branchHash: string | undefined;
  let analysisId: string | undefined;
  let scanStatusUrl: string | undefined;
  let scanStatus: ScanStatus | undefined;

  try {
    const result = await soosAnalysisService.setupScan({
      clientId: args.clientId,
      projectName: args.projectName,
      commitHash: args.commitHash,
      branchName: args.branchName,
      buildVersion: args.buildVersion,
      buildUri: args.buildURI,
      branchUri: args.branchURI,
      integrationType: args.integrationType,
      operatingEnvironment: args.operatingEnvironment,
      integrationName: args.integrationName,
      appVersion: args.appVersion,
      scriptVersion: args.scriptVersion,
      contributingDeveloperAudit: [
        {
          contributingDeveloperId: args.contributingDeveloperId,
          source: args.contributingDeveloperSource,
          sourceName: args.contributingDeveloperSourceName,
        },
      ],
      scanType,
      toolName: SOOS_CSA_CONSTANTS.ToolName,
      commandLine:
        process.argv.length > 2
          ? obfuscateCommandLine(
              reassembleCommandLine(process.argv.slice(2)),
              SOOS_CSA_CONSTANTS.ObfuscatedArguments.map((argument) => `--${argument}`),
            )
          : null,
    });

    projectHash = result.projectHash;
    branchHash = result.branchHash;
    analysisId = result.analysisId;
    scanStatusUrl = result.scanStatusUrl;

    process.chdir(SOOS_CSA_CONSTANTS.WorkingDirectory);
    soosLogger.info("Generating container file for scan");
    await runSyft(args);
    soosLogger.info("Container file generation completed successfully");

    soosLogger.info("Reading results");
    const base64Content = await FileUtilities.readFileToBase64Async(
      SOOS_CSA_CONSTANTS.ResultsFilePath,
    );
    const base64Stream = Readable.from(base64Content);
    const formData = new FormData();
    formData.append("file", base64Stream, SOOS_CSA_CONSTANTS.ResultsFilename);

    soosLogger.info("Uploading results");
    const containerFileUploadResponse =
      await soosAnalysisService.analysisApiClient.uploadManifestFiles({
        clientId: args.clientId,
        projectHash,
        branchHash,
        analysisId,
        manifestFiles: formData,
        hasMoreThanMaximumManifests: false,
      });

    soosLogger.info(
      ` Container Files: \n`,
      `  ${containerFileUploadResponse.message} \n`,
      containerFileUploadResponse.manifests
        ?.map((m) => `  ${m.name}: ${m.statusMessage}`)
        .join("\n"),
    );

    await soosAnalysisService.startScan({
      clientId: args.clientId,
      projectHash,
      analysisId: analysisId,
      scanType,
      scanUrl: result.scanUrl,
    });

    scanStatus = await soosAnalysisService.waitForScanToFinish({
      scanStatusUrl,
      scanUrl: result.scanUrl,
      scanType,
    });

    if (
      isScanDone(scanStatus) &&
      args.exportFormat !== AttributionFormatEnum.Unknown &&
      args.exportFileType !== AttributionFileTypeEnum.Unknown
    ) {
      await soosAnalysisService.generateFormattedOutput({
        clientId: args.clientId,
        projectHash: result.projectHash,
        projectName: args.projectName,
        branchHash: result.branchHash,
        analysisId: result.analysisId,
        format: args.exportFormat,
        fileType: args.exportFileType,
        workingDirectory: SOOS_CSA_CONSTANTS.WorkingDirectory,
      });
    }

    const exitCodeWithMessage = getAnalysisExitCodeWithMessage(
      scanStatus,
      args.integrationName,
      args.onFailure,
    );
    soosLogger.always(`${exitCodeWithMessage.message} - exit ${exitCodeWithMessage.exitCode}`);
    exit(exitCodeWithMessage.exitCode);
  } catch (error) {
    let status = ScanStatus.Error;
    let message = "Error while performing scan.";
    if (error instanceof Error && error.message.includes("NoManifestsAccepted")) {
      status = ScanStatus.NoFiles;
      message = "No manifests were processed successfully.";
    }

    if (projectHash && branchHash && analysisId && (!scanStatus || !isScanDone(scanStatus)))
      await soosAnalysisService.analysisApiClient.updateScanStatus({
        clientId: args.clientId,
        projectHash,
        branchHash,
        scanType,
        scanId: analysisId,
        status,
        message,
      });
    soosLogger.error(error);
    soosLogger.always(`${error} - exit 1`);
    exit(1);
  }
};

(async () => {
  try {
    const args = parseArgs();
    soosLogger.setMinLogLevel(args.logLevel);
    soosLogger.always("Starting SOOS CSA Analysis");
    soosLogger.debug(
      JSON.stringify(
        obfuscateProperties(
          args as unknown as Record<string, unknown>,
          SOOS_CSA_CONSTANTS.ObfuscatedArguments,
        ),
        null,
        2,
      ),
    );

    await runAnalysis(args);
  } catch (error) {
    soosLogger.error(`Error on createAndRun: ${error}`);
    soosLogger.always(`Error on createAndRun: ${error} - exit 1`);
    exit(1);
  }
})();
