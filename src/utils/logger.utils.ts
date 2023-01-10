import winston from 'winston';

//Winston aliases for readability
const combine = winston.format.combine;
const timestamp = winston.format.timestamp;
const prettyPrint = winston.format.prettyPrint;
const colorize =  winston.format.colorize;
const align = winston.format.align;
const printf = winston.format.printf;

const alignedWithColorsAndTime = winston.format.combine(
  colorize(),
  timestamp(),
  align(),
  printf((info) => {
    const {
      timestamp, level, message, ...args
    } = info;

    const ts = timestamp.slice(0, 19).replace('T', ' ');
    return `[${ts} ${level}]: ${message} ${Object.keys(args).length ? JSON.stringify(args, null, 2) : ''}`;
  }),
);

const logger = winston.createLogger({
    level: "debug",
    transports: [
      new winston.transports.File({
        filename: "logs/example.log",
        format: combine(
          timestamp({
            format: "MMM-DD-YYYY HH:mm:ss",
          }),
          prettyPrint()
        )
      }),
      new winston.transports.Console({
        format:  combine(
          timestamp({
            format: "MMM-DD-YYYY HH:mm:ss",
          }), 
          alignedWithColorsAndTime
        )
      })
    ],
  });
  
export {logger};