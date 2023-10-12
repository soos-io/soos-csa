export enum LogLevel {
  PASS = "PASS",
  IGNORE = "IGNORE",
  INFO = "INFO",
  WARN = "WARN",
  FAIL = "FAIL",
  DEBUG = "DEBUG",
  ERROR = "ERROR",
}

export class Logger {
  private verbose: boolean;
  private console: Console;
  private minLogLevel: LogLevel;

  constructor(
    verbose: boolean = false,
    minLogLevel: LogLevel = LogLevel.INFO,
    console: Console = global.console
  ) {
    this.verbose = verbose;
    this.console = console;
    this.minLogLevel = minLogLevel;
  }

  private getTimeStamp(): string {
    const now = new Date();
    const dateString = now.toLocaleString("en-US", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
      timeZoneName: "short",
    });

    return dateString;
  }

  private logWithTimestamp(level: LogLevel, message?: any, ...optionalParams: any[]): void {
    if (level >= this.minLogLevel) {
      const timestamp = this.getTimeStamp();
      const logMessage = `${timestamp} UTC [${level}] ${message}`;
      this.console.log(logMessage, ...optionalParams);
    }
  }

  setVerbose(verbose: boolean) {
    this.verbose = verbose;
  }

  setMinLogLevel(minLogLevel: LogLevel) {
    this.minLogLevel = minLogLevel;
  }

  info(message?: any, ...optionalParams: any[]): void {
    this.logWithTimestamp(LogLevel.INFO, message, ...optionalParams);
  }

  debug(message?: any, ...optionalParams: any[]): void {
    this.logWithTimestamp(LogLevel.DEBUG, message, ...optionalParams);
  }

  warn(message?: any, ...optionalParams: any[]): void {
    this.logWithTimestamp(LogLevel.WARN, message, ...optionalParams);
  }

  error(message?: any, ...optionalParams: any[]): void {
    this.logWithTimestamp(LogLevel.ERROR, message, ...optionalParams);
  }

  verboseInfo(message?: any, ...optionalParams: any[]): void {
    if (this.verbose) {
      this.info(message, ...optionalParams);
    }
  }

  verboseDebug(message?: any, ...optionalParams: any[]): void {
    if (this.verbose) {
      this.debug(message, ...optionalParams);
    }
  }

  verboseWarn(message?: any, ...optionalParams: any[]): void {
    if (this.verbose) {
      this.warn(message, ...optionalParams);
    }
  }

  verboseError(message?: any, ...optionalParams: any[]): void {
    if (this.verbose) {
      this.error(message, ...optionalParams);
    }
  }
}
