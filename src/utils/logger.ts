import pino from 'pino';
const isDev = process.env.NODE_ENV === 'development';

export const logger = pino({
  level: isDev ? 'debug' : 'info',
  transport: isDev
    ? {
        target: 'pino-pretty',
        options: {
          colorize: true,
          ignore: 'pid,hostname',
          translateTime: 'SYS:standard',
        },
      }
    : undefined,
  serializers: {
    err: pino.stdSerializers.err,
    error: pino.stdSerializers.err,
  },
});