/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import i18n from 'i18n'
import cors from 'cors'
import fs from 'node:fs'
import yaml from 'js-yaml'
import config from 'config'
import multer from 'multer'
import helmet from 'helmet'
import http from 'node:http'
import path from 'node:path'
import userRouter from './routes/userRouter'
import express from 'express'
import colors from 'colors/safe'
import serveIndex from 'serve-index'
import bodyParser from 'body-parser'
// @ts-expect-error FIXME due to non-existing type definitions for finale-rest
import * as finale from 'finale-rest'
import compression from 'compression'
// @ts-expect-error FIXME due to non-existing type definitions for express-robots-txt
import robots from 'express-robots-txt'
import cookieParser from 'cookie-parser'
import * as Prometheus from 'prom-client'
import swaggerUi from 'swagger-ui-express'
import featurePolicy from 'feature-policy'
import { IpFilter } from 'express-ipfilter'
// @ts-expect-error FIXME due to non-existing type definitions for express-security.txt
import securityTxt from 'express-security.txt'
import { rateLimit } from 'express-rate-limit'
import type { Request, Response, NextFunction } from 'express'

import winston from 'winston'

// -------------------
// Winston setup
// -------------------
const winstonLogger = winston.createLogger({
  transports: [
    new winston.transports.Console(), // shows logs in terminal
    new winston.transports.File({ filename: 'security.log' }) // saves logs into a file
  ]
})
winstonLogger.info('Application started')

const app = express()

// -------------------
// Winston request logging
// -------------------
app.use((req: Request, res: Response, next: NextFunction) => {
  winstonLogger.info(`Incoming request: ${req.method} ${req.url}`)
  next()
})

const server = new http.Server(app)

// errorhandler requires us from overwriting a string property on it's module which is a big no-no with esmodules :/
const errorhandler = require('errorhandler')

app.set('view engine', 'pug')
app.set('views', path.join(__dirname, 'views'))

// Enable compression
app.use(compression())

// Enable JSON body parser
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

// Cookie parser
app.use(cookieParser())

// Enable localization
i18n.configure({
  locales: ['en', 'de', 'fr'],
  directory: __dirname + '/locales'
})
app.use(i18n.init)

// Enable CORS
app.use(cors())

// Helmet for securing HTTP headers
app.use(helmet())

// Feature Policy
app.use(
  featurePolicy({
    features: {
      fullscreen: ["'self'"],
      vibrate: ["'none'"],
      geolocation: ["'none'"]
    }
  })
)

// Robots.txt
app.use(
  robots({
    UserAgent: '*',
    Disallow: ''
  })
)

// Security.txt
app.use(
  securityTxt({
    contact: 'mailto:security@juice-shop.local',
    encryption: 'https://juice-shop.local/pgp-key.txt',
    acknowledgments: 'https://juice-shop.local/hall-of-fame',
    preferredLanguages: 'en'
  })
)

// Rate limiting
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100
  })
)

// Static files
app.use('/public', express.static(path.join(__dirname, 'public')))
app.use('/uploads', express.static(path.join(__dirname, 'uploads')), serveIndex(path.join(__dirname, 'uploads')))

// Multer for file uploads
const upload = multer({ dest: 'uploads/' })
app.use(upload.single('file'))

// Prometheus metrics
const collectDefaultMetrics = Prometheus.collectDefaultMetrics
collectDefaultMetrics()
app.get('/metrics', async (req: Request, res: Response) => {
  res.set('Content-Type', Prometheus.register.contentType)
  res.end(await Prometheus.register.metrics())
})

// API routes
app.use('/api/users', userRouter)

// Swagger API docs
const swaggerDocument = yaml.load(fs.readFileSync('./swagger.yaml', 'utf8'))
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument))

// Finale-rest setup (example)
finale.initialize({ app, sequelize: {} })

// Error handling
if (process.env.NODE_ENV === 'development') {
  app.use(errorhandler())
} else {
  app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    winstonLogger.error(err.message)
    res.status(500).send('Internal Server Error')
  })
}

// -------------------
// Start server
// -------------------
const port = config.get<number>('port') || 3000
server.listen(port, () => {
  winstonLogger.info(colors.green(`Server running on http://localhost:${port}`))
})

export default server
