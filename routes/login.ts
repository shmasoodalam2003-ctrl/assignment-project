import { type Request, type Response, type NextFunction } from 'express'
import config from 'config'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges, users } from '../data/datacache'
import { BasketModel } from '../models/basket'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

export function login() {
  function afterLogin(user: { data: any, bid: number }, res: Response, next: NextFunction) {
    verifyPostLoginChallenges(user)

    BasketModel.findOrCreate({ where: { UserId: user.data.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        // ✅ Generate JWT with proper structure
        const token = jwt.sign(
          {
            status: 'success',
            data: {
              id: user.data.id,
              email: user.data.email,
              role: user.data.role
            }
          },
          'your-secret-key', // ⚠️ use config.get('application.secret') in real apps
          { expiresIn: '1h' }
        )

        user.bid = basket.id

        // ✅ Only send small response (not giant object)
        res.json({
          authentication: {
            token,
            bid: basket.id,
            umail: user.data.email
          }
        })
      })
      .catch((error: Error) => next(error))
  }

  return async (req: Request, res: Response, next: NextFunction) => {
    verifyPreLoginChallenges(req)

    try {
      const found = await UserModel.findOne({
        where: { email: req.body.email, deletedAt: null }
      })

      if (!found) {
        return res.status(401).send(res.__('Invalid email or password.'))
      }

      const storedHash = (found.get('password') as string) || ''
      const ok = await bcrypt.compare(req.body.password || '', storedHash)

      if (!ok) {
        return res.status(401).send(res.__('Invalid email or password.'))
      }

      const user = utils.queryResultToJson(found)

      // ✅ Handle 2FA (if enabled)
      if (user.data?.id && user.data.totpSecret !== '') {
        return res.status(401).json({
          status: 'totp_token_required',
          data: {
            tmpToken: jwt.sign(
              {
                userId: user.data.id,
                type: 'password_valid_needs_second_factor_token'
              },
              'your-secret-key',
              { expiresIn: '10m' }
            )
          }
        })
      } else if (user.data?.id) {
        return afterLogin(user, res, next)
      } else {
        return res.status(401).send(res.__('Invalid email or password.'))
      }
    } catch (error) {
      next(error)
    }
  }

  function verifyPreLoginChallenges(req: Request) {
    challengeUtils.solveIf(challenges.weakPasswordChallenge, () => {
      return (
        req.body.email === 'admin@' + config.get<string>('application.domain') &&
        req.body.password === 'admin123'
      )
    })
    // 🔹 keep other pre-login challenge checks if needed
  }

  function verifyPostLoginChallenges(user: { data: any }) {
    challengeUtils.solveIf(challenges.loginAdminChallenge, () => user.data.id === users.admin.id)
    // 🔹 keep other post-login challenge checks if needed
  }
}
