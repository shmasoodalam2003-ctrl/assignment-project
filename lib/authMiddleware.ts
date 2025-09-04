import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'

interface AuthRequest extends Request {
  user?: any
}

export function authenticateToken(req: AuthRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) {
    return res.status(401).json({ error: 'Access denied. Token missing.' })
  }

  jwt.verify(token, 'your-secret-key', (err, decoded: any) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' })
    }

    // Some tokens store data in decoded.data, others directly in decoded
    req.user = decoded.data ? decoded.data : decoded  

    next()
  })
}
